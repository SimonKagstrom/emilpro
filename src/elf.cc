#include <elf.hh>
#include <function.hh>
#include <instruction.hh>
#include <disassembly.hh>
#include <utils.hh>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <libelf.h>
#include <map>
#include <string>

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <link.h>

using namespace emilpro;

class Instruction : public IInstruction
{
public:
	Instruction(void *address, const char *disassembled)
		: m_address(address), m_disassembled(disassembled)
	{
	}

	void *getAddress()
	{
		return m_address;
	}

	std::string &disassemble()
	{
		return m_disassembled;
	}

private:
	void *m_address;
	std::string m_disassembled;
};

class Function : public IFunction, IDisassembly::IInstructionListener
{
public:
	Function(const char *name, uint8_t *data, void *addr, size_t size,
			IFunction::FunctionType type)
	{
		m_name = xstrdup(name);
		m_size = size;
		m_entry = addr;
		m_data = data;
		m_type = type;
	}

	virtual ~Function()
	{
		for (InstructionList_t::iterator it = m_instructions.begin();
				it != m_instructions.end();
				it++)
			delete *it;
		m_instructions.clear();

		free((void *)m_name);
	}

	enum IFunction::FunctionType getType()
	{
		return m_type;
	}

	const char *getName()
	{
		return m_name;
	}

	size_t getSize()
	{
		return m_size;
	}

	void *getEntry()
	{
		return m_entry;
	}

	void setAddress(void *addr)
	{
		m_entry = addr;
	}

	void setSize(size_t size)
	{
		m_size = size;
	}

	void disassembleFunction()
	{
		m_instructions.clear();

		IDisassembly::getInstance().execute(this, m_data, m_size);
	}

	InstructionList_t &getInstructions()
	{
	    return m_instructions;
	}

	// These three functions are the IInstructionListerners
	void onInstruction(off_t offset, const char *ascii)
	{
		off_t addr = (off_t)m_entry + offset;

		Instruction *p = new Instruction((void *)addr, ascii);
		m_instructions.push_back(p);
	}

private:
	const char *m_name;
	size_t m_size;
	void *m_entry;
	uint8_t *m_data;
	enum IFunction::FunctionType m_type;

	InstructionList_t m_instructions;
};

class Elf : public IElf
{
public:
	Elf(const char *filename)
	{
		m_elf = NULL;
		m_listener = NULL;
		m_elfMemory = NULL;
		m_filename = strdup(filename);
		m_elfMemory = NULL;
	}

	~Elf()
	{
		free(m_elfMemory);
		free((void *)m_filename);
	}

	bool checkFile()
	{
		Elf *elf;
		bool out = true;
		int fd;

		fd = ::open(m_filename, O_RDONLY, 0);
		if (fd < 0) {
				error("Cannot open %s\n", m_filename);
				return false;
		}



		if (!(elf = elf_begin(fd, ELF_C_READ, NULL)) ) {
				error("elf_begin failed on %s\n", m_filename);
				out = false;
				goto out_open;
		}
		if (!elf32_getehdr(elf)) {
				error("elf32_getehdr failed on %s\n", m_filename);
				out = false;
		}
		elf_end(elf);

out_open:
		close(fd);

		return out;
	}

	bool parse(IFunctionListener *listener)
	{
		m_functionsByAddress.clear();
		m_functionsByName.clear();

		return parseOne(listener);
	}

	bool parseOne(IFunctionListener *listener)
	{
		Elf_Scn *scn = NULL;
		Elf32_Ehdr *ehdr;
		size_t shstrndx;
		bool ret = false;
		int fd;

		m_listener = listener;

		fd = ::open(m_filename, O_RDONLY, 0);
		if (fd < 0) {
				error("Cannot open %s\n", m_filename);
				return false;
		}

		if (!(m_elf = elf_begin(fd, ELF_C_READ, NULL)) ) {
				error("elf_begin failed on %s\n", m_filename);
				goto out_open;
		}


		if (!(ehdr = elf32_getehdr(m_elf))) {
				error("elf32_getehdr failed on %s\n", m_filename);
				goto out_elf_begin;
		}

		if (elf_getshdrstrndx(m_elf, &shstrndx) < 0) {
				error("elf_getshstrndx failed on %s\n", m_filename);
				goto out_elf_begin;
		}

		size_t sz;
		m_elfMemory = (uint8_t *)read_file(&sz, "%s", m_filename);

		while ( (scn = elf_nextscn(m_elf, scn)) != NULL )
		{
			Elf32_Shdr *shdr = elf32_getshdr(scn);
			Elf_Data *data = elf_getdata(scn, NULL);
			char *name;

			name = elf_strptr(m_elf, shstrndx, shdr->sh_name);
			if(!data) {
					error("elf_getdata failed on section %s in %s\n",
							name, m_filename);
					goto out_elf_begin;
			}

			/* Handle symbols */
			if (shdr->sh_type == SHT_SYMTAB)
				handleSymtab(scn);
			if (shdr->sh_type == SHT_DYNSYM)
				handleDynsym(scn);
		}
		elf_end(m_elf);
		if (!(m_elf = elf_begin(fd, ELF_C_READ, NULL)) ) {
			error("elf_begin failed on %s\n", m_filename);
			goto out_open;
		}
		while ( (scn = elf_nextscn(m_elf, scn)) != NULL )
		{
			Elf32_Shdr *shdr = elf32_getshdr(scn);
			char *name = elf_strptr(m_elf, shstrndx, shdr->sh_name);

			// .rel.plt
			if (shdr->sh_type == SHT_REL && strcmp(name, ".rel.plt") == 0)
				handleRelPlt(scn);
		}
		m_fixupFunctions.clear();
		for (FunctionsByAddress_t::iterator it = m_functionsByAddress.begin();
				it != m_functionsByAddress.end();
				it++) {
			Function *fn = it->second;

			m_listener->onFunction(*fn);
		}

		ret = true;

out_elf_begin:
		elf_end(m_elf);
out_open:
		close(fd);

		return ret;
	}

	IFunction *functionByAddress(void *addr)
	{
		return m_functionsByAddress[addr];
	}

	IElf::FunctionList_t functionByName(const char *name)
	{
		return m_functionsByName[std::string(name)];
	}

private:
	class Segment
	{
	public:
		Segment(ElfW(Addr) paddr, ElfW(Addr) vaddr, size_t size, ElfW(Word) align) :
			m_paddr(paddr), m_vaddr(vaddr), m_size(size), m_align(align)
		{
		}

		ElfW(Addr) m_paddr;
		ElfW(Addr) m_vaddr;
		ElfW(Word) m_align;
		size_t m_size;
	};

	typedef std::map<std::string, IElf::FunctionList_t> FunctionsByName_t;
	typedef std::map<void *, Function *> FunctionsByAddress_t;
	typedef std::map<int, Function *> FixupMap_t;
	typedef std::list<Segment> SegmentList_t;

	void *offsetTableToAddress(Elf32_Addr addr)
	{
		/*
		 * The .got.plt table contains a pointer to the push instruction
		 * below:
		 *
		 *  08070f10 <pthread_self@plt>:
		 *   8070f10:       ff 25 58 93 0b 08       jmp    *0x80b9358
		 *   8070f16:       68 b0 06 00 00          push   $0x6b0
		 *
		 * so to get the entry point, we rewind the pointer to the start
		 * of the jmp.
		 */
		return (void *)(addr - 6);
	}

	ElfW(Addr) adjustAddressBySegment(ElfW(Addr) addr)
	{
		for (SegmentList_t::iterator it = m_curSegments.begin();
				it != m_curSegments.end(); it++) {
			Segment cur = *it;

			if (addr >= cur.m_paddr && addr < cur.m_paddr + cur.m_size) {
				addr = (addr - cur.m_paddr + cur.m_vaddr);
				break;
			}
		}

		return addr;
	}

	void handleRelPlt(Elf_Scn *scn)
	{
		Elf32_Shdr *shdr = elf32_getshdr(scn);
		Elf_Data *data = elf_getdata(scn, NULL);
		Elf32_Rel *r = (Elf32_Rel *)data->d_buf;
		int n = data->d_size / sizeof(Elf32_Rel);

		panic_if(n <= 0,
				"Section data too small (%zd) - no symbols\n",
				data->d_size);

		for (int i = 0; i < n; i++, r++) {
			Elf32_Addr *got_plt = (Elf32_Addr *)adjustAddressBySegment(r->r_offset);

			FixupMap_t::iterator it = m_fixupFunctions.find(ELF32_R_SYM(r->r_info));

			if (it == m_fixupFunctions.end())
				continue;
			Function *fn = it->second;

			fn->setAddress(offsetTableToAddress(*got_plt));
			fn->setSize(1);
			m_functionsByAddress[fn->getEntry()] = fn;
		}
	}

	void handleDynsym(Elf_Scn *scn)
	{
		handleSymtabGeneric(scn, IFunction::SYM_DYNAMIC);
	}

	void handleSymtab(Elf_Scn *scn)
	{
		handleSymtabGeneric(scn, IFunction::SYM_NORMAL);
	}

	void handleSymtabGeneric(Elf_Scn *scn, enum IFunction::FunctionType symType)
	{
		Elf32_Shdr *shdr = elf32_getshdr(scn);
		Elf_Data *data = elf_getdata(scn, NULL);
		Elf32_Sym *s = (Elf32_Sym *)data->d_buf;
		int n_syms = 0;
		int n_fns = 0;
		int n_datas = 0;
		int n = data->d_size / sizeof(Elf32_Sym);

		panic_if(n <= 0,
				"Section data too small (%zd) - no symbols\n",
				data->d_size);

		/* Iterate through all symbols */
		for (int i = 0; i < n; i++)
		{
			const char *sym_name = elf_strptr(m_elf, shdr->sh_link, s->st_name);
			int type = ELF32_ST_TYPE(s->st_info);

			/* Ohh... This is an interesting symbol, add it! */
			if ( type == STT_FUNC || type == STT_NOTYPE) {
				Elf_Scn *textScn = elf_getscn(m_elf, s->st_shndx);
				Elf32_Addr addr = adjustAddressBySegment(s->st_value);
				Elf32_Word size = s->st_size;

				if (!textScn) {
					s++;
				    continue;
				}
				Elf32_Shdr *textScnShdr = elf32_getshdr(textScn);

				Function *fn = new Function(sym_name,
						(uint8_t *)m_elfMemory + textScnShdr->sh_offset + (s->st_value - textScnShdr->sh_addr), (void *)addr, size, symType);

				m_functionsByName[std::string(sym_name)].push_back(fn);
				// Needs fixup?
				if (shdr->sh_type == SHT_DYNSYM && size == 0)
					m_fixupFunctions[i] = fn;
				else
					m_functionsByAddress[(void *)addr] = fn;

				fn->disassembleFunction();
			}

			s++;
		}
	}

	FunctionsByName_t m_functionsByName;
	FunctionsByAddress_t m_functionsByAddress;
	FixupMap_t m_fixupFunctions;
	SegmentList_t m_curSegments;

	Elf *m_elf;
	uint8_t *m_elfMemory;
	IFunctionListener *m_listener;
	const char *m_filename;
};

IElf *IElf::open(const char *filename)
{
	static bool initialized = false;
	Elf *p;

	if (!initialized) {
		panic_if(elf_version(EV_CURRENT) == EV_NONE,
				"ELF version failed\n");
		initialized = true;
	}

	p = new Elf(filename);

	if (p->checkFile() == false) {
		delete p;

		return NULL;
	}

	return p;
}
