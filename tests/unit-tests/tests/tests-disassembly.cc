#include "../test.hh"

#include <idisassembly.hh>
#include <iinstruction.hh>
#include <utils.hh>

#include <unordered_map>

using namespace emilpro;


// IA32 code (from coincident unit test)
static uint8_t asm_dump[] =
{
		0x76, 0x27,                         //  0 jbe    804ab40 <ud_decode+0x630>
		0x89, 0x1c, 0x24,                   //  2 mov    %ebx,(%esp)
		0x83, 0xe0, 0x0f,                   //  5 and    $0xf,%eax
		0x8d, 0x50, 0x01,                   //  8 lea    0x1(%eax),%edx
		0xd1, 0xea,                         // 11 shr    %edx
		0x88, 0x55, 0xcc,                   // 13 mov    %dl,-0x34(%ebp)
		0xe8, 0x88, 0xe3, 0xff, 0xff,       // 16 call   8048ef0 <inp_next>
		0x8b, 0x83, 0x58, 0x02, 0x00, 0x00, // 21 mov    0x258(%ebx),%eax
		0xf4,                               // 27 hlt
		0xcc,                               // 28 int3
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
		ASSERT_TRUE(lst.size() == 10U);

		AddressMap_t m = listToAddressMap(lst);
		IInstruction *p;

		p = m[0x1000 +  0]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getEncoding().find("jbe") != std::string::npos);
		ASSERT_TRUE(p->getType() == IInstruction::IT_CFLOW);

		p = m[0x1000 +  2]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getEncoding().find("mov") != std::string::npos);
		ASSERT_TRUE(p->getType() == IInstruction::IT_DATA_HANDLING);

		p = m[0x1000 + 11]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getEncoding().find("shr") != std::string::npos);
		ASSERT_TRUE(p->getType() == IInstruction::IT_ARITHMETIC_LOGIC);

		p = m[0x1000 + 16]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getEncoding().find("call") != std::string::npos);
		ASSERT_TRUE(p->getType() == IInstruction::IT_CFLOW);
		ASSERT_TRUE(p->isPrivileged() == IInstruction::T_false);

		p = m[0x1000 + 27]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getEncoding().find("hlt") != std::string::npos);
		ASSERT_TRUE(p->getType() == IInstruction::IT_OTHER);
		ASSERT_TRUE(p->isPrivileged() == IInstruction::T_true);

		p = m[0x1000 + 28]; ASSERT_TRUE(p);
		ASSERT_TRUE(p->getEncoding().find("int3") != std::string::npos);
		ASSERT_TRUE(p->getType() == IInstruction::IT_OTHER);
		ASSERT_TRUE(p->isPrivileged() == IInstruction::T_false);
	};
}
