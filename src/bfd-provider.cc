#include <isymbolprovider.hh>
#include <symbolfactory.hh>
#include <isymbol.hh>
#include <architecturefactory.hh>
#include <utils.hh>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <map>
#include <list>
#include <string>

#include <bfd.h>

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <link.h>

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



class BfdProvider : public ISymbolProvider
{
public:
	BfdProvider() :
		m_bfd(NULL),
		m_listener(NULL),
		m_elfMemory(NULL),
		m_elfIs32Bit(true)
	{
	}

	virtual ~BfdProvider()
	{
		if (m_bfd)
			bfd_close(m_bfd);
	}

	unsigned match(void *data, size_t dataSize)
	{
		return ISymbolProvider::PERFECT_MATCH;
	}

	bool parse(void *data, size_t dataSize, ISymbolListener *listener)
	{
		asymbol **syms;
		char **matching;
		unsigned int sz;
		long symcount;
		struct target_buffer *buffer = (struct target_buffer *)xmalloc(sizeof(struct target_buffer));

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
			return false;
		}

		ArchitectureFactory::instance().provideArchitecture((ArchitectureFactory::Architecture_t)bfd_get_arch(m_bfd));

		if ((bfd_get_file_flags(m_bfd) & HAS_SYMS) == 0) {
			error("no symbols");
			return false;
		}

		m_listener = listener;

		symcount = bfd_read_minisymbols(m_bfd, FALSE,
				(void **)&syms, &sz);
		if (symcount == 0)
			symcount = bfd_read_minisymbols(m_bfd, TRUE /* dynamic */,
					(void **)&syms, &sz);

		handleSymbols(symcount, syms);

		m_listener = listener;

		free (syms);

		return true;
	}

private:
	void handleSymbols(long symcount, asymbol **syms)
	{
		typedef std::map<ISymbol *, uint64_t> SectionAddressBySymbol_t;
		typedef std::map<uint64_t, ISymbol *> SymbolsByAddress_t;
		typedef std::map<asection *, void *> BfdSectionContents_t;
		typedef std::list<ISymbol *> SymbolList_t;
		SectionAddressBySymbol_t sectionEndAddresses;
		SymbolsByAddress_t symbolsByAddress;
		SymbolList_t fixupSyms;
		BfdSectionContents_t sectionContents;

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

			if (sectionContents.find(cur->section) == sectionContents.end()) {
				bfd_size_type size;
				bfd_byte *p;

				size = bfd_section_size (m_bfd, cur->section);
				p = (bfd_byte *) xmalloc (size);
				if (! bfd_get_section_contents (m_bfd, cur->section, p, 0, size))
					continue;

				sectionContents[cur->section] = p;
			}

			section = (uint8_t *)sectionContents[cur->section];

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
					size);
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

			// Last symbol, fixup via the section size
			if (nextIt == symbolsByAddress.end()) {
				uint64_t lastSectionAddr = sectionEndAddresses[cur];

				if (lastSectionAddr > cur->getAddress())
					cur->setSize(lastSectionAddr - cur->getAddress());
			} else {
				ISymbol *other = nextIt->second;

				cur->setSize(other->getAddress() - cur->getAddress());
			}
		}
		for (SymbolsByAddress_t::iterator it = symbolsByAddress.begin();
				it != symbolsByAddress.end();
				++it) {
			ISymbol *cur = it->second;

			m_listener->onSymbol(*cur);
		}
	}

	struct bfd *m_bfd;
	ISymbolListener *m_listener;
	uint8_t *m_elfMemory;
	bool m_elfIs32Bit;
};


class Registrer
{
public:
	Registrer()
	{
		bfd_init();

		BfdProvider *p = new BfdProvider();

		SymbolFactory::instance().registerProvider(p);
	}
};

static Registrer registrer;
