#include "../test.hh"

#include <xmlfactory.hh>
#include <xmlstring.hh>

#include <utils.hh>
#include <string>
#include <list>

using namespace emilpro;

std::string removeLeadingSpaces(const std::string str)
{
	std::istringstream stream(str);
	std::string out;
	std::string line;

	while (std::getline(stream, line))
	{
		unsigned i = 0;

		while (line[i] == ' ' || line[i] == '\t')
			i++;

		out += line.substr(i, std::string::npos);
	}

	return out;
}

class XmlStringListenerFixture : public XmlFactory::IXmlListener
{
public:
	XmlStringListenerFixture(XmlString *p) :
		m_xmlString(p)
	{
		m_expected = new std::list<const char*>();
		XmlFactory::instance().registerListener("InstructionModel", this);
	}

	~XmlStringListenerFixture()
	{
		XmlFactory::instance().unregisterListener(this);
		delete m_expected;
	}

	void addExpected(const char *str)
	{
		m_expected->push_back(str);
	}

	bool onStart(const Glib::ustring &name, const xmlpp::SaxParser::AttributeList &properties, std::string value)
	{
		return true;
	}

	bool onElement(const Glib::ustring &name, const xmlpp::SaxParser::AttributeList &properties, std::string value)
	{
		return true;
	}

	bool onEnd(const Glib::ustring &name)
	{
		std::string cur = m_expected->front();

		std::string s = m_xmlString->getString();

		ASSERT_TRUE(removeLeadingSpaces(cur) == removeLeadingSpaces(s));

		m_expected->pop_front();

		return true;
	}

private:
	XmlString *m_xmlString;
	std::list<const char *> *m_expected;
};


TESTSUITE(xmlstring)
{
	TEST(instruction)
	{
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

		XmlString xmlString("InstructionModel");

		XmlFactory::instance().parse(xml);

		std::string s = xmlString.getString();
		s =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				"<emilpro>\n" +
				s +
				"</emilpro>";

		ASSERT_TRUE(removeLeadingSpaces(xml) == removeLeadingSpaces(s));
	}

	TEST(multipleInstructions)
	{
		std::string xml =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				"<emilpro>\n"
				"  <InstructionModel name=\"bge\" architecture=\"mips\">\n"
				"    <type>cflow</type>\n"
				"  </InstructionModel>\n"
				"  <InstructionModel name=\"addiu\" architecture=\"mips\">\n"
				"    <type>arithmetic_logic</type>\n"
				"  </InstructionModel>\n"
				"</emilpro>\n";

		XmlString xmlString("InstructionModel");

		XmlStringListenerFixture *lf = new XmlStringListenerFixture(&xmlString);

		lf->addExpected(
				"  <InstructionModel name=\"bge\" architecture=\"mips\">\n"
				"    <type>cflow</type>\n"
				"  </InstructionModel>\n"
				);
		lf->addExpected(
				"  <InstructionModel name=\"addiu\" architecture=\"mips\">\n"
				"    <type>arithmetic_logic</type>\n"
				"  </InstructionModel>\n"
				);

		XmlFactory::instance().parse(xml);

		delete lf;
	}
}
