#include <utils.hh>
#include <emilpro.hh>
#include <instructionfactory.hh>
#include <server/cgi-server.hh>
#include <server/html-generator.hh>

#include <string>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>

using namespace emilpro;

CgiServer::CgiServer() :
				m_timestamp(0xffffffffffffffffULL),
				m_timestampAdjustment(0),
				m_currentArchitecture(bfd_arch_unknown)
{
	InstructionFactory::instance(); // Must be created before this
	XmlFactory::instance().registerListener("ServerTimestamps", this);
}

bool CgiServer::onStart(const Glib::ustring &name, const xmlpp::SaxParser::AttributeList &properties, std::string value)
{
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

void CgiServer::request(const std::string xml)
{
	HtmlGenerator &html = HtmlGenerator::instance();

	// Reset timestamps before parsing
	m_timestamp = 0xffffffffffffffffULL;
	m_timestampAdjustment = 0;
	m_currentArchitecture = bfd_arch_unknown;

	XmlFactory::instance().parse(xml, true);

	html.addData(getenv("REMOTE_ADDR"), m_currentArchitecture);
	html.generate();
}
