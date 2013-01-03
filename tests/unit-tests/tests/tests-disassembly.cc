#include "../test.hh"

#include <architecturefactory.hh>
#include <idisassembly.hh>
#include <iinstruction.hh>
#include <utils.hh>

#include <unordered_map>

using namespace emilpro;


// IA32 code (from coincident unit test)
static uint8_t ia32_dump[] =
{
		0x76, 0x03,                         //     0 jbe    1f
		0x89, 0x1c, 0x24,                   //     2 mov    %ebx,(%esp)
		0x83, 0xe0, 0x0f,                   // 1:  5 and    $0xf,%eax
		0x8d, 0x50, 0x01,                   //     8 lea    0x1(%eax),%edx
		0xd1, 0xea,                         //    11 shr    %edx
		0x88, 0x55, 0xcc,                   //    13 mov    %dl,-0x34(%ebp)
		0xe8, 0x07, 0x00, 0x00, 0x00,       //    16 call   28
		0x8b, 0x83, 0x58, 0x02, 0x00, 0x00, //    21 mov    0x258(%ebx),%eax
		0xf4,                               //    27 hlt
		0xcc,                               //    28 int3
		0xa1, 0x80, 0x00, 0x00, 0x00,       //    29 mov    0x80,%eax
};

// From sample-source.c
static uint8_t ppc32_dump[] =
{
		0x2f, 0x83, 0x00, 0x05, // cmpwi   cr7,r3,5
		0x7c, 0x84, 0x1a, 0x14, // add     r4,r4,r3
		0x41, 0x9d, 0x00, 0x08, // bgt-    cr7,10 <fn+0x10>
		0x7c, 0x64, 0x1b, 0x78, // mr      r4,r3
		0x7c, 0x83, 0x23, 0x78, // mr      r3,r4
		0x4e, 0x80, 0x00, 0x20, // blr

		0x38, 0x80, 0x00, 0x03, // li      r4,3
		0x48, 0x00, 0x00, 0x00, // b       1c <second+0x4>
};

static uint8_t arm_dump[] =
{
		0x04, 0xe0, 0x2d, 0xe5, // push    {lr}        ; (str lr, [sp, #-4]!)
		0x01, 0x00, 0x50, 0xe1, // cmp     r0, r1
		0x04, 0xd0, 0x4d, 0xe2, // sub     sp, sp, #4
		0x00, 0x00, 0xa0, 0xd1, // movle   r0, r0
		0x00, 0x00, 0x00, 0xda, // ble     18 <fn+0x18>
		0xfe, 0xff, 0xff, 0xeb, // bl      0 <__aeabi_idiv>
		0x04, 0xd0, 0x8d, 0xe2, // add     sp, sp, #4
		0x00, 0x80, 0xbd, 0xe8, // pop     {pc}

		0x03, 0x10, 0xa0, 0xe3, // mov     r1, #3
		0xfe, 0xff, 0xff, 0xea, // b       0 <fn>
};

static uint8_t mips_dump[] =
{
		0x00, 0xa4, 0x10, 0x2a, // slt    v0,a1,a0
		0x10, 0x40, 0x00, 0x05, // beqz    v0,1c <fn+0x1c>
		0x00, 0x00, 0x00, 0x00, // nop
		0x00, 0x85, 0x00, 0x1a, // div    zero,a0,a1
		0x00, 0x00, 0x10, 0x12, // mflo    v0
		0x03, 0xe0, 0x00, 0x08, // jr    ra
		0x00, 0x00, 0x00, 0x00, // nop
		0x03, 0xe0, 0x00, 0x08, // jr    ra
		0x00, 0x80, 0x10, 0x21, // move    v0,a0

		0x27, 0xbd, 0xff, 0xe8, // addiu    sp,sp,-24
		0xaf, 0xbf, 0x00, 0x14, // sw    ra,20(sp)
		0x0c, 0x00, 0x00, 0x00, // jal    0 <fn>
		0x24, 0x05, 0x00, 0x03, // li    a1,3
		0x8f, 0xbf, 0x00, 0x14, // lw    ra,20(sp)
		0x00, 0x00, 0x00, 0x00, // nop
		0x03, 0xe0, 0x00, 0x08, // jr    ra
		0x27, 0xbd, 0x00, 0x18, // addiu    sp,sp,24
};

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
		IDisassembly &dis = IDisassembly::instance();

		InstructionList_t lst = dis.execute((void *)ia32_dump, sizeof(ia32_dump), 0x1000);
		ASSERT_TRUE(lst.size() == 11U);

		AddressMap_t m = listToAddressMap(lst);
		IInstruction *p;

		p = m[0x1000 +  0]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getEncoding().find("jbe") != std::string::npos);
		ASSERT_TRUE(p->getMnemonic() == "jbe");
		ASSERT_TRUE(p->getType() == IInstruction::IT_CFLOW);
		ASSERT_TRUE(p->getBranchTargetAddress() == 0x1000 + 5U);

		p = m[0x1000 +  2]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getEncoding().find("mov") != std::string::npos);
		ASSERT_TRUE(p->getMnemonic() == "mov");
		ASSERT_TRUE(p->getType() == IInstruction::IT_DATA_HANDLING);

		p = m[0x1000 + 11]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getEncoding().find("shr") != std::string::npos);
		ASSERT_TRUE(p->getMnemonic() == "shr");
		ASSERT_TRUE(p->getType() == IInstruction::IT_ARITHMETIC_LOGIC);

		p = m[0x1000 + 16]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getEncoding().find("call") != std::string::npos);
		ASSERT_TRUE(p->getMnemonic() == "call");
		ASSERT_TRUE(p->getType() == IInstruction::IT_CFLOW);
		ASSERT_TRUE(p->isPrivileged() == T_false);
		ASSERT_TRUE(p->getBranchTargetAddress() == 0x1000 + 28U);

		p = m[0x1000 + 27]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getEncoding().find("hlt") != std::string::npos);
		ASSERT_TRUE(p->getMnemonic() == "hlt");
		ASSERT_TRUE(p->getType() == IInstruction::IT_OTHER);
		ASSERT_TRUE(p->isPrivileged() == T_true);

		p = m[0x1000 + 28]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getEncoding().find("int3") != std::string::npos);
		ASSERT_TRUE(p->getMnemonic() == "int3");
		ASSERT_TRUE(p->getType() == IInstruction::IT_OTHER);
		ASSERT_TRUE(p->isPrivileged() == T_false);

		p = m[0x1000 + 29]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getEncoding().find("mov") != std::string::npos);
		ASSERT_TRUE(p->getMnemonic() == "mov");
		ASSERT_TRUE(p->getType() == IInstruction::IT_DATA_HANDLING);
		ASSERT_TRUE(p->isPrivileged() == T_false);

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

	TEST(otherArchs, DisassemblyFixture)
	{
		IDisassembly &dis = IDisassembly::instance();
		ArchitectureFactory::instance().provideArchitecture(bfd_arch_powerpc);

		InstructionList_t lst = dis.execute((void *)ppc32_dump, sizeof(ppc32_dump), 0x1000);
		ASSERT_TRUE(lst.size() == 8U);


		AddressMap_t m = listToAddressMap(lst);
		IInstruction *p;

		p = m[0x1000 +  0]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getEncoding().find("cmpwi") != std::string::npos);
		p = m[0x1000 +  8]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getEncoding().find("bgt") != std::string::npos);
		p = m[0x1000 +  24]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getEncoding().find("li") != std::string::npos);


		ArchitectureFactory::instance().provideArchitecture(bfd_arch_mips);
		lst = dis.execute((void *)mips_dump, sizeof(mips_dump), 0x1000);
		ASSERT_TRUE(lst.size() == 17U);

		m = listToAddressMap(lst);
		p = m[0x1000 +  0]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getEncoding().find("slt") != std::string::npos);
		p = m[0x1000 +  4]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getEncoding().find("beqz") != std::string::npos);
		p = m[0x1000 + 20]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getEncoding().find("jr") != std::string::npos);


		ArchitectureFactory::instance().provideArchitecture(bfd_arch_arm);
		lst = dis.execute((void *)arm_dump, sizeof(arm_dump), 0x1000);
		ASSERT_TRUE(lst.size() == 10U);

		m = listToAddressMap(lst);
		p = m[0x1000 +  0]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getEncoding().find("push") != std::string::npos);
		p = m[0x1000 +  4]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getEncoding().find("cmp") != std::string::npos);
		p = m[0x1000 + 16]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getEncoding().find("ble") != std::string::npos);

		ArchitectureFactory::instance().destroy();
	}
}
