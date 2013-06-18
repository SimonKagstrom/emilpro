#include <utils.hh>
#include <emilpro.hh>
#include <instructionfactory.hh>
#include <server/cgi-server.hh>

#include <string>
#include <fstream>
#include <stdio.h>

using namespace emilpro;

CgiServer::CgiServer() :
				m_timestamp(0xffffffffffffffffULL),
				m_timestampAdjustment(0)
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
	if (m_timestamp == 0xffffffffffffffffULL)
		return "";

	InstructionFactory::InstructionModelList_t lst = InstructionFactory::instance().getInstructionModels();
	std::list<InstructionFactory::IInstructionModel *> models;
	uint64_t highestTimestamp = 1;

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

	out += fmt(
			"  <ServerTimestamps>\n"
			"    <Timestamp>%lld</Timestamp>\n"
			"  </ServerTimestamps>\n",
			(unsigned long long)highestTimestamp
			);

	for (std::list<InstructionFactory::IInstructionModel *>::iterator it = models.begin();
			it != models.end();
			++it) {
		InstructionFactory::IInstructionModel *cur = *it;

		out += cur->toXml();
	}

	return  "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
			"<emilpro>\n" +
			out +
			"</emilpro>\n";
}

void CgiServer::request(const std::string xml)
{
	// Reset timestamps before parsing
	m_timestamp = 0xffffffffffffffffULL;
	m_timestampAdjustment = 0;

	XmlFactory::instance().parse(xml, true);
}
