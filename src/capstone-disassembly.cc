#include <idisassemblyprovider.hh>
#include <architecturefactory.hh>
#include <instructionfactory.hh>
#include <preferences.hh>
#include <utils.hh>

#include <capstone/capstone.h>

#include <memory>

using namespace emilpro;

class CapstoneDisassembly : public Preferences::IListener
{
public:
	CapstoneDisassembly(ArchitectureFactory::Architecture_t arch)
	{
		cs_arch cs_arch = CS_ARCH_MAX;// Illegal

		if (arch == bfd_arch_powerpc)
			cs_arch = CS_ARCH_PPC;
		else if (arch == bfd_arch_arm)
			cs_arch = CS_ARCH_ARM;
		else if (arch == bfd_arch_i386)
			cs_arch = CS_ARCH_X86;
		else if (arch == bfd_arch_mips)
			cs_arch = CS_ARCH_MIPS;
		else
			panic("Illegal architecture %u\n", arch);

		auto err = cs_open(cs_arch, CS_MODE_LITTLE_ENDIAN, &m_handle);
		if (err != CS_ERR_OK)
			panic("Can't open capstone\n");

	    Preferences::instance().registerListener("X86InstructionSyntax", this);
	}

	virtual ~CapstoneDisassembly()
	{
		cs_close(&m_handle);
	}

	InstructionList_t execute(void *p, size_t size, uint64_t address)
	{
		InstructionFactory &factory = InstructionFactory::instance();
		InstructionList_t out;
		cs_insn *insns = NULL;

		auto n = cs_disasm(m_handle, (const uint8_t *)p, size, address, 0, &insns);

		for (unsigned i = 0; i < n; i++)
		{
			auto p = &insns[i];

			std::vector<std::string> encodingVec;
			std::string str = fmt("%s\t%s", p->mnemonic, p->op_str);

			encodingVec.push_back(p->mnemonic);

			for (const auto &it : split_string(p->op_str, ",\t"))
				encodingVec.push_back(it);

			IInstruction *insn = factory.create(address, p->address - address, encodingVec, str, (uint8_t *)p->bytes, p->size);

			if (insn)
				out.push_back(insn);
		}

		cs_free(insns, n);

		return out;
	}

private:
	void onPreferencesChanged(const std::string &key,
			const std::string &oldValue, const std::string &newValue)
	{
		if (key != "X86InstructionSyntax")
			return;

		size_t option = CS_OPT_SYNTAX_ATT;

		if (newValue == "intel")
			option = CS_OPT_SYNTAX_INTEL;

		cs_option(m_handle, CS_OPT_SYNTAX, option);
	}


	csh m_handle;
};


class CapstoneDisassembmblerProvider : public IDisassemblyProvider,
	public std::enable_shared_from_this<IDisassemblyProvider>
{
public:
	CapstoneDisassembmblerProvider()
	{
		InstructionFactory::instance().registerProvider(std::shared_ptr<IDisassemblyProvider>(this));
	}

	virtual ~CapstoneDisassembmblerProvider()
	{
	}

	unsigned match(void *data, size_t dataSize)
	{
		auto arch = ArchitectureFactory::instance().getArchitecture();

		// Other architectures are handled by the BFD disassembler
		if (arch != bfd_arch_powerpc &&
				arch != bfd_arch_arm &&
				arch != bfd_arch_sparc &&
				arch != bfd_arch_i386 &&
				arch != bfd_arch_mips)
			return 0;


		if (!m_instance)
			m_instance = std::unique_ptr<CapstoneDisassembly>(new CapstoneDisassembly(arch));

		// Higher than BFD
		return 1000;
	}

	InstructionList_t execute(void *data, size_t size, uint64_t address)
	{
		return m_instance->execute(data, size, address);
	}

	bool relativeAddressOffsets()
	{
		return false;
	}

private:
	std::unique_ptr<CapstoneDisassembly> m_instance;
};

class CapstoneDisassemblyCreator
{
public:
	CapstoneDisassemblyCreator()
	{
		// Deleted by the shared_ptr above
		new CapstoneDisassembmblerProvider();
	}
};

static CapstoneDisassemblyCreator g_capstoneDisassembler;
