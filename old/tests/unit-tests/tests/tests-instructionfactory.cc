#include "../test.hh"

#include <xmlfactory.hh>
#include <configuration.hh>
#include <emilpro.hh>

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

		InstructionList_t lst = InstructionFactory::instance().disassemble((void *)mips_dump, sizeof(mips_dump), 0x1000);
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


		lst = InstructionFactory::instance().disassemble((void *)mips_dump, sizeof(mips_dump), 0x1000);
		ASSERT_TRUE(lst.size() == 1U);
		insn = lst.front();
		ASSERT_TRUE(insn->getMnemonic() == "beqz");
		ASSERT_TRUE(insn->getType() == IInstruction::IT_CFLOW);
	}

	TEST(modelToFromXml)
	{
		InstructionFactory &insnFactory = InstructionFactory::instance();
		XmlFactory &x = XmlFactory::instance();

		std::string xml =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				"<emilpro>\n"
				"  <InstructionModel name=\"beqz\" architecture=\"mips\" timestamp=\"2\">\n"
				"    <type>cflow</type>\n"
				"    <privileged>false</privileged>\n"
				"    <description>Branch if greater or equal\n"
				"           Yada yada."
				"    </description>\n"
				"  </InstructionModel>\n"
				"</emilpro>\n";

		ArchitectureFactory::instance().provideArchitecture(bfd_arch_mips);

		x.parse(xml);
		InstructionModel *p = (InstructionModel *)insnFactory.m_instructionModelByArchitecture[(unsigned)bfd_arch_mips]["beqz"];
		ASSERT_TRUE(p);

		xml = p->toXml();
		insnFactory.m_instructionModelByArchitecture[(unsigned)bfd_arch_mips]["beqz"] = NULL;
		x.parse(xml);
		InstructionModel *p2 = (InstructionModel *)insnFactory.m_instructionModelByArchitecture[(unsigned)bfd_arch_mips]["beqz"];
		ASSERT_TRUE(p2);

		ASSERT_TRUE(p->m_addressReferenceIndex == p2->m_addressReferenceIndex);
		ASSERT_TRUE(p->m_architecture == p2->m_architecture);
		ASSERT_TRUE(p->m_description == p2->m_description);
		ASSERT_TRUE(p->m_mnemonic == p2->m_mnemonic);
		ASSERT_TRUE(p->m_privileged == p2->m_privileged);
		ASSERT_TRUE(p->m_type == p2->m_type);
		ASSERT_TRUE(p->m_timestamp == p2->m_timestamp);
	}

	TEST(timestamp)
	{
		InstructionFactory &insnFactory = InstructionFactory::instance();
		XmlFactory &x = XmlFactory::instance();

		std::string xml =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				"<emilpro>\n"
				"  <InstructionModel name=\"beqz\" architecture=\"mips\" timestamp=\"1\">\n"
				"    <type>cflow</type>\n"
				"  </InstructionModel>\n"
				"  <InstructionModel name=\"beqz\" architecture=\"mips\" timestamp=\"3\">\n"
				"    <type>data_handling</type>\n"
				"  </InstructionModel>\n"
				"  <InstructionModel name=\"beqz\" architecture=\"mips\" timestamp=\"2\">\n"
				"    <type>other</type>\n"
				"  </InstructionModel>\n"
				"</emilpro>\n";

		ArchitectureFactory::instance().provideArchitecture(bfd_arch_mips);

		x.parse(xml);
		InstructionModel *p = (InstructionModel *)insnFactory.m_instructionModelByArchitecture[(unsigned)bfd_arch_mips]["beqz"];
		ASSERT_TRUE(p);

		ASSERT_TRUE(p->getType() == IInstruction::IT_DATA_HANDLING);
		EmilPro::destroy();
	}

	TEST(timestampDefault)
	{
		InstructionFactory &insnFactory = InstructionFactory::instance();
		XmlFactory &x = XmlFactory::instance();

		std::string xml =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				"<emilpro>\n"
				"  <InstructionModel name=\"beqz\" architecture=\"mips\" timestamp=\"1\">\n"
				"    <type>cflow</type>\n"
				"  </InstructionModel>\n"
				"  <InstructionModel name=\"beqz\" architecture=\"mips\">\n" // No timestamp - now
				"    <type>data_handling</type>\n"
				"  </InstructionModel>\n"
				"  <InstructionModel name=\"beqz\" architecture=\"mips\" timestamp=\"2\">\n"
				"    <type>other</type>\n"
				"  </InstructionModel>\n"
				"</emilpro>\n";

		ArchitectureFactory::instance().provideArchitecture(bfd_arch_mips);

		x.parse(xml);
		InstructionModel *p = (InstructionModel *)insnFactory.m_instructionModelByArchitecture[(unsigned)bfd_arch_mips]["beqz"];
		ASSERT_TRUE(p);

		ASSERT_TRUE(p->getType() == IInstruction::IT_DATA_HANDLING);
		EmilPro::destroy();
	}

	TEST(getModels)
	{
		InstructionFactory &insnFactory = InstructionFactory::instance();
		XmlFactory &x = XmlFactory::instance();

		std::string xml =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				"<emilpro>\n"
				"  <InstructionModel name=\"beqz\" architecture=\"mips\" timestamp=\"0\">\n"
				"    <type>cflow</type>\n"
				"  </InstructionModel>\n"
				"  <InstructionModel name=\"sub\" architecture=\"mips\" timestamp=\"3\">\n"
				"    <type>data_handling</type>\n"
				"  </InstructionModel>\n"
				"  <InstructionModel name=\"addiu\" architecture=\"mips\" timestamp=\"5\">\n"
				"    <type>other</type>\n"
				"  </InstructionModel>\n"
				"</emilpro>\n";

		ArchitectureFactory::instance().provideArchitecture(bfd_arch_mips);

		x.parse(xml);
		InstructionFactory::InstructionModelList_t lst;

		lst = insnFactory.getInstructionModels();
		ASSERT_TRUE(lst.size() == 3U);
		lst = insnFactory.getInstructionModels(6);
		ASSERT_TRUE(lst.size() == 0U);

		lst = insnFactory.getInstructionModels(1);
		ASSERT_TRUE(lst.size() == 2U);

		lst = insnFactory.getInstructionModels(3);
		ASSERT_TRUE(lst.size() == 2U);

		lst = insnFactory.getInstructionModels(4);
		ASSERT_TRUE(lst.size() == 1U);
	}

	TEST(xmlSpecialCharacters)
	{
		InstructionFactory &insnFactory = InstructionFactory::instance();
		XmlFactory &x = XmlFactory::instance();
		std::string description  = "Branch & if > greater \' or \" equal < after the less";
		bool res;

		std::string xml =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				"<emilpro>\n"
				"  <InstructionModel name=\"beqz\" architecture=\"mips\" timestamp=\"2\">\n"
				"    <type>cflow</type>\n"
				"    <privileged>false</privileged>\n"
				"    <description>" + escape_string_for_xml(description) + "</description>\n"
				"  </InstructionModel>\n"
				"</emilpro>\n";

		ArchitectureFactory::instance().provideArchitecture(bfd_arch_mips);

		res = x.parse(xml);
		ASSERT_TRUE(res);
		InstructionModel *p = (InstructionModel *)insnFactory.m_instructionModelByArchitecture[(unsigned)bfd_arch_mips]["beqz"];
		ASSERT_TRUE(p);

		ASSERT_TRUE(p->m_description == description);
	}

	TEST(scrubHtml)
	{
		InstructionFactory &insnFactory = InstructionFactory::instance();
		XmlFactory &x = XmlFactory::instance();
		std::string description  = "<b>KALLE</b>";
		bool res;

		std::string xml =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				"<emilpro>\n"
				"  <InstructionModel name=\"beqz\" architecture=\"mips\" timestamp=\"2\">\n"
				"    <type>cflow</type>\n"
				"    <privileged>false</privileged>\n"
				"    <description>" + escape_string_for_xml(description) + "</description>\n"
				"  </InstructionModel>\n"
				"</emilpro>\n";

		ArchitectureFactory::instance().provideArchitecture(bfd_arch_mips);

		res = x.parse(xml);
		ASSERT_TRUE(res);
		InstructionModel *p = (InstructionModel *)insnFactory.m_instructionModelByArchitecture[(unsigned)bfd_arch_mips]["beqz"];
		ASSERT_TRUE(p);

		std::string scrubbed = p->toXml();
		ASSERT_TRUE(scrubbed.find("<description>KALLE</description>") != std::string::npos);

		Configuration::instance().setCapabilties(Configuration::CAP_HTML_DESCRIPTIONS);
		scrubbed = p->toXml();
		ASSERT_TRUE(scrubbed.find(fmt("<description>%s</description>", escape_string_for_xml(description).c_str())) != std::string::npos);
	}
}
