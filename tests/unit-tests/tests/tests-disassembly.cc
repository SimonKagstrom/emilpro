#include "../test.hh"

#include <idisassembly.hh>
#include <iinstruction.hh>
#include <utils.hh>

#include <unordered_map>

using namespace emilpro;


// IA32 code (from coincident unit test)
static uint8_t asm_dump[] =
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

class DisassemblyFixture
{
public:
	typedef std::unordered_map<uint64_t, IInstruction *> AddressMap_t;

	AddressMap_t listToAddressMap(IDisassembly::InstructionList_t &lst)
	{
		AddressMap_t out;

		for (IDisassembly::InstructionList_t::iterator it = lst.begin();
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
		IDisassembly &dis = IDisassembly::getInstance();

		IDisassembly::InstructionList_t lst = dis.execute((void *)asm_dump, sizeof(asm_dump), 0x1000);
		ASSERT_TRUE(lst.size() == 11U);

		AddressMap_t m = listToAddressMap(lst);
		IInstruction *p;

		p = m[0x1000 +  0]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getEncoding().find("jbe") != std::string::npos);
		ASSERT_TRUE(p->getType() == IInstruction::IT_CFLOW);
		ASSERT_TRUE(p->getBranchTargetAddress() == 0x1000 + 5U);

		p = m[0x1000 +  2]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getEncoding().find("mov") != std::string::npos);
		ASSERT_TRUE(p->getType() == IInstruction::IT_DATA_HANDLING);

		p = m[0x1000 + 11]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getEncoding().find("shr") != std::string::npos);
		ASSERT_TRUE(p->getType() == IInstruction::IT_ARITHMETIC_LOGIC);

		p = m[0x1000 + 16]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getEncoding().find("call") != std::string::npos);
		ASSERT_TRUE(p->getType() == IInstruction::IT_CFLOW);
		ASSERT_TRUE(p->isPrivileged() == T_false);
		ASSERT_TRUE(p->getBranchTargetAddress() == 0x1000 + 28U);

		p = m[0x1000 + 27]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getEncoding().find("hlt") != std::string::npos);
		ASSERT_TRUE(p->getType() == IInstruction::IT_OTHER);
		ASSERT_TRUE(p->isPrivileged() == T_true);

		p = m[0x1000 + 28]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getEncoding().find("int3") != std::string::npos);
		ASSERT_TRUE(p->getType() == IInstruction::IT_OTHER);
		ASSERT_TRUE(p->isPrivileged() == T_false);

		p = m[0x1000 + 29]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getEncoding().find("mov") != std::string::npos);
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
}
