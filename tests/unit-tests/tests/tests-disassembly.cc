#include "../test.hh"

#include <architecturefactory.hh>
#include <instructionfactory.hh>
#include <idisassembly.hh>
#include <iinstruction.hh>
#include <configuration.hh>
#include <emilpro.hh>
#include <utils.hh>

#include <unordered_map>

using namespace emilpro;

#include "assembly-dumps.h"

class DisassemblyFixture
{
public:
	typedef std::unordered_map<uint64_t, IInstruction *> AddressMap_t;

	AddressMap_t listToAddressMap(InstructionList_t &lst)
	{
		AddressMap_t out;

		for (InstructionList_t::iterator it = lst.begin();
				it != lst.end();
				++it) {
			IInstruction *cur = *it;

			out[cur->getAddress()] = cur;
		}

		return out;
	}
};

TESTSUITE(disassembly)
{
	TEST(ia32, DisassemblyFixture)
	{
		EmilPro::init();

		IDisassembly &dis = IDisassembly::instance();
		ArchitectureFactory::instance().provideArchitecture(bfd_arch_i386, bfd_mach_i386_i386);

		InstructionList_t lst = dis.execute((void *)ia32_dump, sizeof(ia32_dump), 0x1000);
		ASSERT_TRUE(lst.size() == 11U);

		AddressMap_t m = listToAddressMap(lst);
		IInstruction *p;
		uint8_t *d;
		size_t sz;

		p = m[0x1000 +  0]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getString().find("jbe") != std::string::npos);
		ASSERT_TRUE(p->getMnemonic() == "jbe");
		ASSERT_TRUE(p->getType() == IInstruction::IT_CFLOW);
		ASSERT_TRUE(p->getBranchTargetAddress() == 0x1000 + 5U);

		p = m[0x1000 +  2]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getString().find("mov") != std::string::npos);
		ASSERT_TRUE(p->getMnemonic() == "mov");
		ASSERT_TRUE(p->getType() == IInstruction::IT_DATA_HANDLING);
		d = p->getRawData(sz);
		ASSERT_TRUE(sz == 3U);
		ASSERT_TRUE(memcmp(d, &ia32_dump[2], sz) == 0);

		p = m[0x1000 + 11]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getString().find("shr") != std::string::npos);
		ASSERT_TRUE(p->getMnemonic() == "shr");
		ASSERT_TRUE(p->getType() == IInstruction::IT_ARITHMETIC_LOGIC);

		p = m[0x1000 + 16]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getString().find("call") != std::string::npos);
		ASSERT_TRUE(p->getMnemonic() == "call");
		ASSERT_TRUE(p->getType() == IInstruction::IT_CALL);
		ASSERT_TRUE(p->isPrivileged() == T_false);
		ASSERT_TRUE(p->getBranchTargetAddress() == 0x1000 + 28U);

		p = m[0x1000 + 27]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getString().find("hlt") != std::string::npos);
		ASSERT_TRUE(p->getMnemonic() == "hlt");
		ASSERT_TRUE(p->getType() == IInstruction::IT_OTHER);
		ASSERT_TRUE(p->isPrivileged() == T_true);

		p = m[0x1000 + 28]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getString().find("int3") != std::string::npos);
		ASSERT_TRUE(p->getMnemonic() == "int3");
		ASSERT_TRUE(p->getType() == IInstruction::IT_OTHER);
		ASSERT_TRUE(p->isPrivileged() == T_false);

		p = m[0x1000 + 29]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getString().find("mov") != std::string::npos);
		ASSERT_TRUE(p->getMnemonic() == "mov");
		ASSERT_TRUE(p->getType() == IInstruction::IT_DATA_HANDLING);
		ASSERT_TRUE(p->isPrivileged() == T_false);
	};

	// NYI
	DISABLED_TEST(ia32_operands, DisassemblyFixture)
	{
		EmilPro::init();

		IDisassembly &dis = IDisassembly::instance();
		ArchitectureFactory::instance().provideArchitecture(bfd_arch_i386);

		InstructionList_t lst = dis.execute((void *)ia32_dump, sizeof(ia32_dump), 0x1000);
		ASSERT_TRUE(lst.size() == 11U);

		AddressMap_t m = listToAddressMap(lst);
		IInstruction *p;

		p = m[0x1000 +  0]; ASSERT_TRUE(p);

		IInstruction::OperandList_t opList = p->getOperands();
		ASSERT_TRUE(opList.size() == 2U);
		IOperand *src = opList.front();   // movl   0x80, %eax   # src, dest
		IOperand *dst = opList.back();

		ASSERT_TRUE(src->isTarget() == T_false);
		ASSERT_TRUE(dst->isTarget() == T_true);
		// ASSERT_TRUE(src->getType() == IOperand::OP_IMMEDIATE); // Should really be OP_ADDRESS
		ASSERT_TRUE(dst->getType() == IOperand::OP_REGISTER);

		ASSERT_TRUE(src->getValue() == 0x80U);
	};

	TEST(ia32Prefixes, DisassemblyFixture)
	{
		IDisassembly &dis = IDisassembly::instance();
		ArchitectureFactory::instance().provideArchitecture(bfd_arch_i386);

		InstructionList_t lst = dis.execute((void *)ia32_prefix_dump, sizeof(ia32_prefix_dump), 0x1000);
		ASSERT_TRUE(lst.size() == 1U);

		AddressMap_t m = listToAddressMap(lst);
		IInstruction *p;

		p = m[0x1000 +  0]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getMnemonic() == "incl");
	};

	TEST(otherArchs, DisassemblyFixture)
	{
		IDisassembly &dis = IDisassembly::instance();
		ArchitectureFactory::instance().provideArchitecture(bfd_arch_powerpc);

		InstructionList_t lst = dis.execute((void *)ppc32_dump, sizeof(ppc32_dump), 0x1000);
		ASSERT_TRUE(lst.size() == 8U);


		AddressMap_t m = listToAddressMap(lst);
		IInstruction *p;
		uint8_t *d;
		size_t sz;

		p = m[0x1000 +  0]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getString().find("cmpwi") != std::string::npos);
		p = m[0x1000 +  8]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getString().find("bgt") != std::string::npos);
		d = p->getRawData(sz);
		ASSERT_TRUE(sz == 4U);
		ASSERT_TRUE(memcmp(d, &ppc32_dump[8], sz) == 0);
		p = m[0x1000 +  24]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getString().find("li") != std::string::npos);


		ArchitectureFactory::instance().provideArchitecture(bfd_arch_mips);
		lst = dis.execute((void *)mips_dump, sizeof(mips_dump), 0x1000);
		ASSERT_TRUE(lst.size() == 17U);

		m = listToAddressMap(lst);
		p = m[0x1000 +  0]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getString().find("slt") != std::string::npos);
		ASSERT_TRUE(p->getMnemonic() == "slt");
		p = m[0x1000 +  4]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getString().find("beqz") != std::string::npos);
		ASSERT_TRUE(p->getMnemonic() == "beqz");
		p = m[0x1000 + 20]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getString().find("jr") != std::string::npos);
		ASSERT_TRUE(p->getMnemonic() == "jr");
		d = p->getRawData(sz);
		ASSERT_TRUE(sz == 4U);
		ASSERT_TRUE(memcmp(d, &mips_dump[20], sz) == 0);


		ArchitectureFactory::instance().provideArchitecture(bfd_arch_arm);
		lst = dis.execute((void *)arm_dump, sizeof(arm_dump), 0x1000);
		ASSERT_TRUE(lst.size() == 10U);

		m = listToAddressMap(lst);
		p = m[0x1000 +  0]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getString().find("push") != std::string::npos);
		ASSERT_TRUE(p->getMnemonic() == "push");
		p = m[0x1000 +  4]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getString().find("cmp") != std::string::npos);
		ASSERT_TRUE(p->getMnemonic() == "cmp");
		p = m[0x1000 + 16]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getString().find("ble") != std::string::npos);
		ASSERT_TRUE(p->getMnemonic() == "ble");

		EmilPro::destroy();
	}

	TEST(memLeaks)
	{
		ASSERT_SCOPE_HEAP_LEAK_FREE
		{
			IDisassembly &dis = IDisassembly::instance();
			uint8_t breakpoint = 0xcc;

			InstructionList_t lst = dis.execute((void *)&breakpoint, sizeof(breakpoint), 0x1000);
			ASSERT_TRUE(lst.size() == 1U);

			for (InstructionList_t::iterator it = lst.begin();
					it != lst.end();
					++it) {
				delete *it;
			}

			EmilPro::destroy();
		}
	}

	TEST(architectures)
	{
		ArchitectureFactory &af = ArchitectureFactory::instance();

		ArchitectureFactory::Architecture_t arch;
		std::string s;

		arch = af.getArchitectureFromName("kalle");
		ASSERT_TRUE(arch == bfd_arch_unknown);

		arch = af.getArchitectureFromName("powerpc");
		ASSERT_TRUE(arch == bfd_arch_powerpc);

		s = af.getNameFromArchitecture(bfd_arch_powerpc);
		ASSERT_TRUE(s == "powerpc");

		s = af.getNameFromArchitecture(bfd_arch_i386);
		ASSERT_TRUE(s == "i386");

		s = af.getNameFromArchitecture(bfd_arch_mips);
		ASSERT_TRUE(s == "mips");

		af.destroy();
	}
}
