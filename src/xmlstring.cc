#include <xmlstring.hh>

#include <utils.hh>

using namespace emilpro;

XmlString::XmlString(const std::string& tag) :
		m_level(0),
		m_string(""),
		m_tag(tag)
{
	XmlFactory::instance().registerListener(tag, this, true);
}

XmlString::~XmlString()
{
	XmlFactory::instance().unregisterListener(this);
}

std::string emilpro::XmlString::getString()
{
	return m_string;
}

bool XmlString::onStart(const Glib::ustring& name,
		const xmlpp::SaxParser::AttributeList& properties, std::string value)
{
	indent();

	m_string += "<" + name + handleProperties(properties) + ">\n";
	m_level++;

	return true;
}

bool XmlString::onElement(const Glib::ustring& name,
		const xmlpp::SaxParser::AttributeList& properties, std::string value)
{
	indent();
	m_string += "<" + name + handleProperties(properties) + ">" + escape_string_for_xml(value);

	return true;
}

bool XmlString::onEnd(const Glib::ustring& name)
{
	if (name == m_tag) {
		indent();
		m_level--;
	}

	m_string += "</" + name + ">\n";

	return true;
}

std::string XmlString::handleProperties(const xmlpp::SaxParser::AttributeList& properties)
{
	std::string out;

	for(xmlpp::SaxParser::AttributeList::const_iterator it = properties.begin();
			it != properties.end();
			++it)
		out += " " + it->name + "=\"" + escape_string_for_xml(it->value) + "\"";

	return out;
}

void emilpro::XmlString::clear()
{
	m_string = "";
}

void XmlString::indent()
{
	for (unsigned i = 0; i < m_level * 4; i++)
		m_string += " ";
}


