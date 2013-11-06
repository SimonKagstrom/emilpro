#include <stdio.h>
#include <stdint.h>

#include <map>
#include <vector>

#include <bfd.h>
#include <dis-asm.h>

#include <architecturefactory.hh>
#include <instructionfactory.hh>
#include <idisassembly.hh>
#include <iinstruction.hh>
#include <utils.hh>

using namespace emilpro;

class Disassembly : public IDisassembly, ArchitectureFactory::IArchitectureListener
{
public:
	Disassembly()
	{
		memset(&m_info, 0, sizeof(m_info));
	    m_list = NULL;
	    m_startAddress = 0;
	    m_disassembler = NULL;

	    m_arch[bfd_arch_i386] = BfdArch(bfd_arch_i386, bfd_mach_i386_i386, print_insn_i386);
	    m_arch[bfd_arch_powerpc] = BfdArch(bfd_arch_powerpc, bfd_mach_ppc_e500mc64, print_insn_big_powerpc);
	    m_arch[bfd_arch_arm] = BfdArch(bfd_arch_arm, bfd_mach_arm_unknown, print_insn_little_arm);
	    m_arch[bfd_arch_mips] = BfdArch(bfd_arch_mips, bfd_mach_mips10000, print_insn_big_mips);
	}

	void init()
	{
	    // Some "sane" default
		setArchitecture(&m_arch[bfd_arch_i386]);

	    ArchitectureFactory::instance().registerListener(this);
	}

	virtual ~Disassembly()
	{
	}

	virtual void onArchitectureDetected(ArchitectureFactory::Architecture_t arch)
	{
		ArchitectureBfdMap_t::iterator it = m_arch.find(arch);

		if (it != m_arch.end())
		{
			setArchitecture(&it->second);
		}
	}

	InstructionList_t execute(void *p, size_t size, uint64_t address)
	{
		InstructionList_t out;
		uint8_t *data = (uint8_t *)p;

		if (!data || size == 0)
			return out;

		InstructionFactory &factory = InstructionFactory::instance();

		m_list = &out;
		m_startAddress = address;

		m_info.buffer_vma = 0;
		m_info.buffer_length = size;
		m_info.buffer = (bfd_byte *)p;
		m_info.stream = (void *)this;

		uint64_t pc = 0;
		int count;
		do
		{
			m_instructionStr.clear();
			m_instructionVector.clear();
			count = m_disassembler(pc, &m_info);

			if (count < 0)
				break;

			IInstruction *insn = factory.create(m_startAddress, pc, m_instructionVector,
					m_instructionStr, (uint8_t *)p + pc, count);

			if (insn)
				m_list->push_back(insn);

			pc += count;
		} while (count > 0 && pc < size);

		return out;
	}

	void destroy();

private:
	class BfdArch
	{
	public:
		BfdArch()
		{
		}

		BfdArch(enum bfd_architecture arch,	unsigned long mach, disassembler_ftype cb) :
			bfd_arch(arch), bfd_mach(mach), callback(cb)
		{
		}

		enum bfd_architecture bfd_arch;
		unsigned long bfd_mach;
		disassembler_ftype callback;
	};

	typedef std::map<ArchitectureFactory::Architecture_t, BfdArch> ArchitectureBfdMap_t;

	void setArchitecture(BfdArch *arch)
	{
	    init_disassemble_info(&m_info, (void *)this, Disassembly::opcodesFprintFuncStatic);

		m_info.arch = arch->bfd_arch;
		m_info.mach = arch->bfd_mach;
		m_disassembler = arch->callback;
		disassemble_init_for_target(&m_info);
		m_info.application_data = (void *)this;

	}

	void opcodesFprintFunc(const char *str)
	{
		std::string stdStr(str);

		m_instructionVector.push_back(trimString(stdStr));
		m_instructionStr += str;
	}

	static int opcodesFprintFuncStatic(void *info, const char *fmt, ...)
	{
	    Disassembly *pThis = (Disassembly *)info;
		char str[64];
	    int out;

	    va_list args;
	    va_start (args, fmt);
	    out = vsnprintf( str, sizeof(str) - 1, fmt, args );
	    va_end (args);

	    pThis->opcodesFprintFunc(str);

	    return out;
	}

	struct disassemble_info m_info;
	disassembler_ftype m_disassembler;
	ArchitectureBfdMap_t m_arch;

	InstructionList_t *m_list;
	uint64_t m_startAddress;
	uint8_t *m_encoding;

	std::string m_instructionStr;
	std::vector<std::string> m_instructionVector;
};

static Disassembly *g_instance;
void Disassembly::destroy()
{
	g_instance = NULL;

	delete this;
}


IDisassembly &IDisassembly::instance()
{
	if (!g_instance) {
		g_instance = new Disassembly();

		g_instance->init();
	}

	return *g_instance;
}
