#include "../test.hh"

#include <xmlfactory.hh>
#include <idisassembly.hh>

#include <utils.hh>

#include "../../../src/instructionfactory.cc"

using namespace emilpro;

TESTSUITE(instruction_factory)
{
	TEST(instructionModelXml)
	{
		InstructionFactory &insnFactory = InstructionFactory::instance();
		XmlFactory &x = XmlFactory::instance();
		const uint8_t mips_dump[] =
		{
				0x10, 0x40, 0x00, 0x05, // beqz    v0,1c <fn+0x1c>
		};
		std::string xml =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				"<emilpro>\n"
				"  <InstructionModel name=\"beqz\" architecture=\"mips\">\n"
				"    <type>cflow</type>\n"
				"    <privileged>false</privileged>\n"
				"    <encoding>0x??ab</encoding>\n"
				"    <encoding>0x??cd</encoding>\n"
				"    <description>Branch if greater or equal\n"
				"           Yada yada."
				"    </description>\n"
				"  </InstructionModel>\n"
				"  <InstructionModel name=\"beqz\" architecture=\"i386\">\n" // Same name, other architecture
				"    <type>data_handling</type>\n"
				"  </InstructionModel>\n"
				"</emilpro>\n";

		ArchitectureFactory::instance().provideArchitecture(bfd_arch_mips);
		IDisassembly &dis = IDisassembly::instance();

		InstructionList_t lst = dis.execute((void *)mips_dump, sizeof(mips_dump), 0x1000);
		ASSERT_TRUE(lst.size() == 1U);
		IInstruction *insn = lst.front();
		ASSERT_TRUE(insn->getMnemonic() == "beqz");
		ASSERT_TRUE(insn->getType() == IInstruction::IT_UNKNOWN);


		ASSERT_TRUE(!insnFactory.m_instructionModelByArchitecture[(unsigned)bfd_arch_mips]["beqz"]);
		x.parse(xml);
		InstructionFactory::IInstructionModel *p = insnFactory.m_instructionModelByArchitecture[(unsigned)bfd_arch_mips]["beqz"];
		ASSERT_TRUE(p);

		ASSERT_TRUE(p->getType() == IInstruction::IT_CFLOW);
		ASSERT_TRUE(p->isPrivileged() == T_false);


		lst = dis.execute((void *)mips_dump, sizeof(mips_dump), 0x1000);
		ASSERT_TRUE(lst.size() == 1U);
		insn = lst.front();
		ASSERT_TRUE(insn->getMnemonic() == "beqz");
		ASSERT_TRUE(insn->getType() == IInstruction::IT_CFLOW);
	}
}
