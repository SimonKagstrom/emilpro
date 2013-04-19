#include <network-listener.hh>
#include <xmlfactory.hh>
#include <xmlstring.hh>
#include <configuration.hh>
#include <utils.hh>

using namespace emilpro;

class InstructionModelListener : public XmlFactory::IXmlListener
{
public:
	InstructionModelListener() :
		m_xmlString("InstructionModel")
	{
		XmlFactory::instance().registerListener("InstructionModel", this);
	}

	~InstructionModelListener()
	{
		XmlFactory::instance().unregisterListener(this);
	}


	bool onStart(const Glib::ustring &name, const xmlpp::SaxParser::AttributeList &properties, std::string value)
	{
		if (name != "InstructionModel")
			return true;

		for(xmlpp::SaxParser::AttributeList::const_iterator it = properties.begin();
				it != properties.end();
				++it) {
			if (it->name == "name") {
				m_currentName = it->value;
			} else if (it->name == "architecture") {
				m_currentArchitecture = it->value;
			}
		}

		return true;
	}

	bool onElement(const Glib::ustring &name, const xmlpp::SaxParser::AttributeList &properties, std::string value)
	{
		return true;
	}

	bool onEnd(const Glib::ustring &name)
	{
		if (name != "InstructionModel")
			return true;

		if (XmlFactory::instance().isParsingRemoteData()) {
			Configuration &conf = Configuration::instance();
			std::string remoteDir = conf.getPath(Configuration::DIR_REMOTE);

			std::string xml = m_xmlString.getString();
			write_file(xml.c_str(), xml.size(), "%s/%s/%s.xml",
					remoteDir.c_str(), m_currentArchitecture.c_str(), m_currentName.c_str());
		}

		return true;
	}

private:
	XmlString m_xmlString;
	std::string m_currentName;
	std::string m_currentArchitecture;
};


NetworkListener::NetworkListener()
{
	m_modelListener = new InstructionModelListener();
}

NetworkListener::~NetworkListener()
{
}


void NetworkListener::onConnectResult(bool connected, const std::string& status)
{
}

void NetworkListener::onXml(const std::string& xml)
{
	XmlFactory::instance().parse(xml, true);
}
