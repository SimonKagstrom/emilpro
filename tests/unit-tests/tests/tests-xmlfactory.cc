#include "../test.hh"

#include <xmlfactory.hh>

#include <utils.hh>

using namespace emilpro;

class ListenerFixture : public XmlFactory::IXmlListener
{
public:
	bool onStart(const Glib::ustring &name, const xmlpp::SaxParser::AttributeList &properties, std::string value)
	{
		m_startElementMap[name]++;
		m_nameToValueMap[name] = value;

		return true;
	}

	bool onElement(const Glib::ustring &name, const xmlpp::SaxParser::AttributeList &properties, std::string value)
	{
		m_elementMap[name]++;
		m_nameToValueMap[name] = value;

		return true;
	}

	bool onEnd(const Glib::ustring &name)
	{
		m_endElementMap[name]++;

		return true;
	}

	std::unordered_map<std::string, unsigned> m_startElementMap;
	std::unordered_map<std::string, unsigned> m_elementMap;
	std::unordered_map<std::string, unsigned> m_endElementMap;
	std::unordered_map<std::string, std::string> m_nameToValueMap;
};

TESTSUITE(xmlfactory)
{
	TEST(createAndDestroy)
	{
		ASSERT_SCOPE_HEAP_LEAK_FREE
		{
			XmlFactory &x = XmlFactory::instance();

			x.destroy();
		}
	}

	TEST(parse, ListenerFixture)
	{
//		ASSERT_SCOPE_HEAP_LEAK_FREE
		{
			XmlFactory &x = XmlFactory::instance();
			bool res;

			x.registerListener("InstructionModel", this);

			res = x.parse(
					"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
					"  <InstructionModel name=\"bge\">\n"
					"  </InstructionModel>\n"
					"<fml></iml>");
			ASSERT_TRUE(res == false);

			ASSERT_TRUE(m_startElementMap["InstructionModel"] == 0U);
			res = x.parse(
					"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
					"<emilpro>\n"
					"  <InstructionModel name=\"bge\" architecture=\"mips\">\n"
					"    <type>cflow</type>\n"
					"    <privileged>unknown</privileged>\n"
					"    <encoding>0x??ab</encoding>\n"
					"    <encoding>0x??cd</encoding>\n"
					"    <description>Branch if greater or equal\n"
					"           Yada yada."
					"    </description>\n"
					"  </InstructionModel>\n"
					"</emilpro>\n"
					);
			ASSERT_TRUE(res == true);
			ASSERT_TRUE(m_startElementMap["InstructionModel"] == 1U);
			ASSERT_TRUE(m_elementMap["type"] == 1U);
			ASSERT_TRUE(m_nameToValueMap["type"] == "cflow");
			ASSERT_TRUE(m_elementMap["privileged"] == 1U);
			ASSERT_TRUE(m_nameToValueMap["privileged"] == "unknown");
			ASSERT_TRUE(m_elementMap["encoding"] == 2U);
			ASSERT_TRUE(m_endElementMap["InstructionModel"] == 1U);

			x.destroy();
		}
	}

	TEST(unregisterListener, ListenerFixture)
	{
		XmlFactory &x = XmlFactory::instance();
		bool res;
		std::string xml =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				"<emilpro>\n"
				"  <InstructionModel name=\"bge\" architecture=\"mips\">\n"
				"    <type>cflow</type>\n"
				"    <privileged>unknown</privileged>\n"
				"    <encoding>0x??ab</encoding>\n"
				"    <encoding>0x??cd</encoding>\n"
				"    <description>Branch if greater or equal\n"
				"           Yada yada."
				"    </description>\n"
				"  </InstructionModel>\n"
				"</emilpro>\n";


		x.registerListener("InstructionModel", this);

		res = x.parse(xml);
		ASSERT_TRUE(res == true);

		ASSERT_TRUE(m_startElementMap["InstructionModel"] == 1U);
		res = x.parse(xml);
		ASSERT_TRUE(res == true);
		ASSERT_TRUE(m_startElementMap["InstructionModel"] == 2U);

		x.unregisterListener(this);

		res = x.parse(xml);
		ASSERT_TRUE(res == true);
		ASSERT_TRUE(m_startElementMap["InstructionModel"] == 2U);

		x.destroy();
	}

	TEST(unregisterMultipleListeners, ListenerFixture)
	{
		XmlFactory &x = XmlFactory::instance();

		x.registerListener("InstructionModel", this);
		x.registerListener("ServerTimestamps", this);
		ASSERT_TRUE(x.m_elementListeners.size() == 2U);

		x.unregisterListener(this);
		ASSERT_TRUE(x.m_elementListeners.size() == 0U);

		x.destroy();
	}

	TEST(runMultipleListeners, ListenerFixture)
	{
		XmlFactory &x = XmlFactory::instance();
		bool res;
		std::string xml =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				"<emilpro>\n"
				"  <ServerTimestamps>\n"
				"    <ServerTimestampDiff>0</ServerTimestampDiff>\n"
				"  </ServerTimestamps>\n"
				"  <InstructionModel name=\"bge\" architecture=\"mips\">\n"
				"    <type>cflow</type>\n"
				"  </InstructionModel>\n"
				"</emilpro>\n";

		x.registerListener("ServerTimestamps", this);
		x.registerListener("InstructionModel", this);

		res = x.parse(xml);
		ASSERT_TRUE(res == true);

		ASSERT_TRUE(m_startElementMap["InstructionModel"] == 1U);
		ASSERT_TRUE(m_startElementMap["ServerTimestamps"] == 1U);

		x.destroy();
	}

	TEST(invalidCharacters, ListenerFixture)
	{
		XmlFactory &x = XmlFactory::instance();
		std::string description  = "Branch & if > greater \' or \" equal < after the less";

		bool res;

		x.registerListener("InstructionModel", this);

		res = x.parse(
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				"<emilpro>\n"
				"  <InstructionModel name=\"bge\">\n"
				"    <description>" + description + "</description>\n"
				"  </InstructionModel>\n"
				"</emilpro>");
		ASSERT_TRUE(res == false);

		res = x.parse(
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				"<emilpro>\n"
				"  <InstructionModel name=\"bge\">\n"
				"    <description>" + escape_string_for_xml(description) + "</description>\n"
				"  </InstructionModel>\n"
				"</emilpro>");
		ASSERT_TRUE(res == true);

		ASSERT_TRUE(m_nameToValueMap["description"] == description);
	}
}
