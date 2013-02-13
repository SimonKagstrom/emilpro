#include <isymbolprovider.hh>
#include <ilineprovider.hh>
#include <symbolfactory.hh>
#include <isymbol.hh>
#include <architecturefactory.hh>
#include <utils.hh>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <map>
#include <unordered_map>
#include <list>
#include <string>

#include <bfd.h>
#include <libelf.h>

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <link.h>

#include "providers.hh"

using namespace emilpro;


struct target_buffer
{
  uint8_t *base;
  size_t size;
};

/* Openning the file is a no-op.  */

static void *
mem_bfd_iovec_open (struct bfd *abfd, void *open_closure)
{
  return open_closure;
}

/* Closing the file is just freeing the base/size pair on our side.  */

static int
mem_bfd_iovec_close (struct bfd *abfd, void *stream)
{
  free (stream);
  return 1;
}

/* For reading the file, we just need to pass through to target_read_memory and
   fix up the arguments and return values.  */

static file_ptr
mem_bfd_iovec_pread (struct bfd *abfd, void *stream, void *buf,
                     file_ptr nbytes, file_ptr offset)
{
  struct target_buffer *buffer = (struct target_buffer *) stream;

  /* If this read will read all of the file, limit it to just the rest.  */
  if (offset + nbytes > (ssize_t)buffer->size)
    nbytes = buffer->size - offset;

  /* If there are no more bytes left, we've reached EOF.  */
  if (nbytes == 0)
    return 0;

  memcpy(buf, buffer->base + offset, nbytes);

  return nbytes;
}

/* For statting the file, we only support the st_size attribute.  */

static int
mem_bfd_iovec_stat (struct bfd *abfd, void *stream, struct stat *sb)
{
  struct target_buffer *buffer = (struct target_buffer*) stream;

  sb->st_size = buffer->size;
  return 0;
}



class BfdProvider : public ISymbolProvider, public ILineProvider
{
public:
	BfdProvider() :
		m_bfd(NULL),
		m_listener(NULL),
		m_symcount(0),
		m_bfdSyms(NULL)
	{
	}

	virtual ~BfdProvider()
	{
		for (BfdSectionContents_t::iterator it = m_sectionContents.begin();
				it != m_sectionContents.end();
				++it) {
			void *p = it->second;

			free(p);
		}

		if (m_bfd) {
			free (m_bfdSyms);
			bfd_close(m_bfd);
			m_bfd = NULL;
		}
	}

	// From ILineProvider
	ILineProvider::FileLine getLineByAddress(uint64_t addr)
	{
		ILineProvider::FileLine out;

		BfdSectionByAddress_t::iterator it = m_sectionByAddress.lower_bound(addr);
		if (it == m_sectionByAddress.end())
			return out;

		asection *section = it->second;

		if (!section)
			return out;

		const char *fileName;
		const char *function;
		unsigned int lineNr;

		if (bfd_find_nearest_line(m_bfd, section, m_bfdSyms, addr - section->vma,
				&fileName, &function, &lineNr)) {
			if (!fileName)
				return out;

			out.m_file = fileName;
			out.m_lineNr = lineNr;
			out.m_isValid = true;
		}

		return out;
	}

	// From ISymbolProvider
	unsigned match(void *data, size_t dataSize)
	{
		return ISymbolProvider::PERFECT_MATCH - 1;
	}

	bool parse(void *data, size_t dataSize, ISymbolListener *listener)
	{
		char **matching;
		unsigned int sz;
		struct target_buffer *buffer = (struct target_buffer *)xmalloc(sizeof(struct target_buffer));

		if (m_bfd) {
			free (m_bfdSyms);
			bfd_close(m_bfd);
			m_bfd = NULL;
		}

		buffer->base = (uint8_t *)data;
		buffer->size = dataSize;
		m_bfd = bfd_openr_iovec ("", NULL,
                          mem_bfd_iovec_open,
                          buffer,
                          mem_bfd_iovec_pread,
                          mem_bfd_iovec_close,
                          mem_bfd_iovec_stat);

		if (!m_bfd) {
			error("bfd_openr failed");
			return false;
		}
		if (! bfd_check_format_matches (m_bfd, bfd_object, &matching)) {
			error("not matching %s", bfd_errmsg( bfd_get_error() ));
			bfd_close(m_bfd);
			m_bfd =  NULL;
			return false;
		}

		if (bfd_get_arch(m_bfd) == bfd_arch_unknown)
			guessArchitecture(data, dataSize);
		ArchitectureFactory::instance().provideArchitecture((ArchitectureFactory::Architecture_t)bfd_get_arch(m_bfd));

		if ((bfd_get_file_flags(m_bfd) & HAS_SYMS) == 0) {
			error("no symbols");
			bfd_close(m_bfd);
			m_bfd =  NULL;
			return false;
		}

		m_listener = listener;

		m_symcount = bfd_read_minisymbols(m_bfd, FALSE,
				(void **)&m_bfdSyms, &sz);
		if (m_symcount == 0)
			m_symcount = bfd_read_minisymbols(m_bfd, TRUE /* dynamic */,
					(void **)&m_bfdSyms, &sz);

		handleSymbols(m_symcount, m_bfdSyms);

		// Add the file symbol
		ISymbol &sym = SymbolFactory::instance().createSymbol(
				ISymbol::LINK_NORMAL,
				ISymbol::SYM_FILE,
				"file",
				data,
				0,
				dataSize,
				false,
				false
		);

		m_listener->onSymbol(sym);

		return true;
	}

private:
	void guessArchitecture(void *data, size_t dataSize)
	{
		struct Elf *elf;
		std::unordered_map<uint64_t, const char *> archMap;

		archMap[EM_386] = "i386";
		archMap[EM_X86_64] = "i386";
		archMap[EM_PPC] = "powerpc";
		archMap[EM_PPC64] = "powerpc";
		archMap[EM_MIPS] = "mips";
		archMap[EM_MIPS_RS3_LE] = "mips";
		archMap[EM_ARM] = "arm";
		archMap[EM_AVR] = "avr";
		archMap[EM_SPARC] = "sparc";
		archMap[EM_SPARCV9] = "sparc";
		archMap[EM_SPARC32PLUS] = "sparc";

		// Not an ELF?
		if (!(elf = elf_memory((char *)data, dataSize)) )
			return;

		size_t sz;
		char *raw = elf_getident(elf, &sz);
		bool elfIs32Bit = false;

		if (raw && sz > EI_CLASS)
			elfIs32Bit = raw[EI_CLASS] == ELFCLASS32;

		// Already coincides with e_machine
		unsigned int arch = EM_NONE;
		if (elfIs32Bit) {
			Elf32_Ehdr *ehdr = elf32_getehdr(elf);

			if (ehdr)
				arch = ehdr->e_machine;
		} else {
			Elf64_Ehdr *ehdr = elf64_getehdr(elf);

			if (ehdr)
				arch = ehdr->e_machine;
		}

		const char *p = archMap[arch];
		if (p) {
			const bfd_arch_info_type *info = bfd_scan_arch(p);

			if (info)
				bfd_set_arch_info(m_bfd, info);
		}

		elf_end(elf);
	}

	void handleSymbols(long symcount, asymbol **syms)
	{
		typedef std::map<ISymbol *, uint64_t> SectionAddressBySymbol_t;
		typedef std::map<uint64_t, ISymbol *> SymbolsByAddress_t;
		typedef std::list<ISymbol *> SymbolList_t;
		SectionAddressBySymbol_t sectionEndAddresses;
		SymbolsByAddress_t symbolsByAddress;
		SymbolList_t fixupSyms;

		for (long i = 0; i < symcount; i++) {
			asymbol *cur = syms[i];
			enum ISymbol::SymbolType symType;
			const char *symName;
			uint64_t symAddr;
			uint64_t size;
			uint8_t *section;

			// An interesting symbol?
			if (cur->flags & (BSF_DEBUGGING | BSF_DEBUGGING_RELOC | BSF_FILE | BSF_RELC | BSF_WARNING | BSF_SRELC))
				continue;

			if ((cur->section->flags & SEC_ALLOC) == 0)
				continue;

			if (m_sectionContents.find(cur->section) == m_sectionContents.end()) {
				bfd_size_type size;
				bfd_byte *p;

				size = bfd_section_size (m_bfd, cur->section);
				p = (bfd_byte *) xmalloc (size);
				if (! bfd_get_section_contents (m_bfd, cur->section, p, 0, size)) {
					free((void *)size);
					continue;
				}

				m_sectionContents[cur->section] = p;
			}

			section = (uint8_t *)m_sectionContents[cur->section];

			symType = ISymbol::SYM_TEXT;
			symName = bfd_asymbol_name(cur);
			symAddr = bfd_asymbol_value(cur);
			size = 0;

			if (cur->flags & BSF_OBJECT) {
				symType = ISymbol::SYM_DATA;
			} else {
				if (cur->section->flags & SEC_CODE)
					symType = ISymbol::SYM_TEXT;
				else if (cur->section->flags & SEC_ALLOC)
					symType = ISymbol::SYM_DATA;
			}
			ISymbol &sym = SymbolFactory::instance().createSymbol(
					ISymbol::LINK_NORMAL,
					symType,
					symName,
					section + cur->value,
					symAddr,
					size,
					cur->section->flags & SEC_ALLOC,
					!(cur->section->flags & SEC_READONLY)
					);
			symbolsByAddress[symAddr] = &sym;
			sectionEndAddresses[&sym] = bfd_section_vma(m_bfd, cur->section) + bfd_section_size(m_bfd, cur->section);

			if (size == 0)
				fixupSyms.push_back(&sym);
		}

		for (SymbolList_t::iterator it = fixupSyms.begin();
				it != fixupSyms.end();
				++it) {
			ISymbol *cur = *it;
			SymbolsByAddress_t::iterator myIt = symbolsByAddress.find(cur->getAddress());

			if (myIt == symbolsByAddress.end())
				continue;

			SymbolsByAddress_t::iterator nextIt = std::next(myIt);
			uint64_t lastSectionAddr = sectionEndAddresses[cur];

			// Last symbol, fixup via the section size
			if (nextIt != symbolsByAddress.end() &&
					nextIt->second->getAddress() <= lastSectionAddr) {
				ISymbol *other = nextIt->second;

				cur->setSize(other->getAddress() - cur->getAddress());
			} else {
				if (lastSectionAddr > cur->getAddress())
					cur->setSize(lastSectionAddr - cur->getAddress());
			}
		}
		for (SymbolsByAddress_t::iterator it = symbolsByAddress.begin();
				it != symbolsByAddress.end();
				++it) {
			ISymbol *cur = it->second;

			m_listener->onSymbol(*cur);
		}

		// Provide section symbols
		for (BfdSectionContents_t::iterator it = m_sectionContents.begin();
				it != m_sectionContents.end();
				++it) {
			asection *section = it->first;

			m_sectionByAddress[(uint64_t)bfd_section_vma(m_bfd, section)] = section;

			ISymbol &sym = SymbolFactory::instance().createSymbol(
					ISymbol::LINK_NORMAL,
					ISymbol::SYM_SECTION,
					bfd_section_name(m_bfd, section),
					it->second,
					(uint64_t)bfd_section_vma(m_bfd, section),
					(uint64_t)bfd_section_size(m_bfd, section),
					false,
					false
					);

			m_listener->onSymbol(sym);
		}
	}

	typedef std::map<asection *, void *> BfdSectionContents_t;
	typedef std::map<uint64_t, asection *> BfdSectionByAddress_t;

	struct bfd *m_bfd;
	ISymbolListener *m_listener;
	long m_symcount;
	asymbol **m_bfdSyms;


	BfdSectionContents_t m_sectionContents;
	BfdSectionByAddress_t m_sectionByAddress;
};

namespace emilpro
{
	static bool g_bfdInited;

	ISymbolProvider *createBfdProvider()
	{
		if (!g_bfdInited) {
			bfd_init();
			g_bfdInited = true;
		}

		BfdProvider *out = new BfdProvider();

		SymbolFactory::instance().registerProvider(out);
		SymbolFactory::instance().registerLineProvider(out);

		return out;
	}
}
