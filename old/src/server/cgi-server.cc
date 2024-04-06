#include <utils.hh>
#include <emilpro.hh>
#include <instructionfactory.hh>
#include <server/cgi-server.hh>
#include <server/html-generator.hh>
#include <configuration.hh>

#include <string>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>

using namespace emilpro;

CgiServer::CgiServer() :
				m_timestamp(0xffffffffffffffffULL),
				m_timestampAdjustment(0),
				m_currentArchitecture(bfd_arch_unknown),
				m_hasCurrentArchitecture(false),
				m_optOutFromStatistics(false)
{
	InstructionFactory::instance(); // Must be created before this
	XmlFactory::instance().registerListener("ServerTimestamps", this);
}

bool CgiServer::onStart(const Glib::ustring &name, const xmlpp::SaxParser::AttributeList &properties, std::string value)
{
	if (name != "ServerTimestamps")
		return true;

	for(xmlpp::SaxParser::AttributeList::const_iterator it = properties.begin();
			it != properties.end();
			++it) {
		if (it->name == "optOutFromStatistics") {
			m_optOutFromStatistics = it->value == "yes" ? true : false;
		}
	}

	return true;
}

bool CgiServer::onElement(const Glib::ustring &name, const xmlpp::SaxParser::AttributeList &properties, std::string value)
{
	if (name == "InstructionModelTimestamp") {
		if (string_is_integer(value))
			m_timestamp = string_to_integer(value);
	} else if (name == "Timestamp") {
		if (string_is_integer(value))
			m_timestampAdjustment = get_utc_timestamp() - string_to_integer(value);
	} else if (name == "CurrentArchitecture") {
		m_currentArchitecture = ArchitectureFactory::instance().getArchitectureFromName(value);
		m_hasCurrentArchitecture = true;
	} else if (name == "CurrentIP") {
		m_remoteIp = value;
	} else if (name == "ClientCapabilities") {
		if (string_is_integer(value))
			Configuration::instance().setCapabilties((Configuration::Capabilities_t)string_to_integer(value));
	}

	return true;
}

CgiServer::~CgiServer()
{
}

bool CgiServer::onEnd(const Glib::ustring &name)
{
	return true;
}


std::string CgiServer::reply()
{
	InstructionFactory::InstructionModelList_t lst = InstructionFactory::instance().getInstructionModels();
	std::list<InstructionFactory::IInstructionModel *> models;
	uint64_t highestTimestamp = 0;

	for (InstructionFactory::InstructionModelList_t::iterator it = lst.begin();
			it != lst.end();
			++it) {
		InstructionFactory::IInstructionModel *cur = *it;

		if (cur->getTimeStamp() > m_timestamp)
			models.push_back(cur);

		if (cur->getTimeStamp() > highestTimestamp)
			highestTimestamp = cur->getTimeStamp();
	}

	std::string out;

	if (m_timestampAdjustment) {
		out = fmt(
				"  <ServerTimestamps>\n"
				"    <ServerTimestampDiff>%lld</ServerTimestampDiff>\n"
				"  </ServerTimestamps>\n",
				(long long)m_timestampAdjustment
				);
	}

	// We want one newer than this
	if (highestTimestamp > 0)
		highestTimestamp++;

	out += fmt(
			"  <ServerTimestamps>\n"
			"    <Timestamp>%lld</Timestamp>\n"
			"  </ServerTimestamps>\n",
			(unsigned long long)highestTimestamp
			);

	uint64_t now = get_utc_timestamp();
	for (std::list<InstructionFactory::IInstructionModel *>::iterator it = models.begin();
			it != models.end();
			++it) {
		InstructionFactory::IInstructionModel *cur = *it;

		// Not newer than now, please! It's an attempt to subvert the server!
		if (cur->getTimeStamp() > now)
			cur->setTimeStamp(now);

		out += cur->toXml();
	}

	return  "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
			"<emilpro>\n" +
			out +
			"</emilpro>\n";
}

bool CgiServer::request(const std::string xml)
{
	HtmlGenerator &html = HtmlGenerator::instance();

	// Reset state before parsing
	m_timestamp = 0xffffffffffffffffULL;
	m_timestampAdjustment = 0;
	m_currentArchitecture = bfd_arch_unknown;
	m_hasCurrentArchitecture = false;
	m_optOutFromStatistics = false;
	Configuration::instance().setCapabilties(Configuration::CAP_NONE);

	if (!XmlFactory::instance().parse(xml, true))
		return false;

	if (m_hasCurrentArchitecture && !m_optOutFromStatistics)
		html.addData(m_remoteIp.c_str(), m_currentArchitecture);
	html.generate();

	return true;
}

void emilpro::CgiServer::startup()
{
	HtmlGenerator &html = HtmlGenerator::instance();

	html.generate();
}
