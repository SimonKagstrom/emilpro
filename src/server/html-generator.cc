#include <server/html-generator.hh>
#include <configuration.hh>
#include <utils.hh>

#include <list>

using namespace emilpro;

void HtmlGenerator::addData(const char* ip, ArchitectureFactory::Architecture_t arch)
{
	const char *country = GeoIP_country_name_by_addr(m_gip, ip);

	if (!country)
		country = "Unknown";

	m_countryCount[country]++;
	m_architectureCount[arch]++;
	m_totalConnections++;
}

void HtmlGenerator::generate()
{
	std::string html = produceHtml();
	std::string xml = toXml();

	std::string statsPath = Configuration::instance().getPath(Configuration::DIR_SERVER_STATISTICS);
	std::string configurationPath = Configuration::instance().getPath(Configuration::DIR_CONFIGURATION);

	write_file(html.c_str(), html.size(), "%s/stats.html", statsPath.c_str());
	write_file(xml.c_str(), xml.size(), "%s/server-statistics.xml", configurationPath.c_str());
}

static HtmlGenerator *g_instance;
void HtmlGenerator::destroy()
{
	g_instance = NULL;
	delete this;
}

HtmlGenerator& HtmlGenerator::instance()
{
	if (!g_instance)
		g_instance = new HtmlGenerator();

	return *g_instance;
}

HtmlGenerator::HtmlGenerator() :
		m_totalConnections(0)
{
	m_gip = GeoIP_open("/usr/share/GeoIP/GeoIP.dat", GEOIP_STANDARD | GEOIP_CHECK_CACHE);

	panic_if(!m_gip,
			"Can't open GeoIP database");

	XmlFactory::instance().registerListener("HtmlGenerator", this);
	XmlFactory::instance().registerListener("InstructionModel", this);
}

HtmlGenerator::~HtmlGenerator()
{
	XmlFactory::instance().unregisterListener(this);
	GeoIP_delete(m_gip);
}

bool HtmlGenerator::onStart(const Glib::ustring& name,
		const xmlpp::SaxParser::AttributeList& properties, std::string value)
{
	std::string insnArch;
	std::string insnName;
	uint64_t timestamp = 0;

	if (name != "InstructionModel")
		return true;

	for(xmlpp::SaxParser::AttributeList::const_iterator it = properties.begin();
			it != properties.end();
			++it) {
		if (it->name == "architecture") { // InstructionModel
			insnArch = it->value;
		} else if (it->name == "name") {
			insnName = it->value;
		} else if (it->name == "timestamp") {
			if (string_is_integer(it->value))
				timestamp = string_to_integer(it->value);
		}
	}

	m_instructionArchitectureCount[ArchitectureFactory::instance().getArchitectureFromName(insnArch)]++;

	if (insnName != "")
		m_lastInstructions[timestamp] = fmt("%s (%s)", insnName.c_str(), insnArch.c_str());

	return true;
}

bool HtmlGenerator::onElement(const Glib::ustring& name,
		const xmlpp::SaxParser::AttributeList& properties, std::string value)
{
	std::string nameStr = "";
	uint64_t valueNum = 0xffffffffffffffffULL;
	std::string insnArchStr;

	for(xmlpp::SaxParser::AttributeList::const_iterator it = properties.begin();
			it != properties.end();
			++it) {
		if (it->name == "name") { // HtmlGenerator
			nameStr = it->value;
		} else if (it->name == "architecture") { // InstructionModel
			insnArchStr = it->value;
		}
	}

	if (name != "CountryCount" && name != "ArchitectureCount") {
		return true;
	}

	if (string_is_integer(value, 10))
		valueNum = string_to_integer(value);

	// Invalid or not set
	if (nameStr == "" || valueNum == 0xffffffffffffffffULL)
		return true;

	if (name == "CountryCount") {
		m_countryCount[nameStr] += valueNum;
		m_totalConnections += valueNum;
	} else if (name == "ArchitectureCount") {
		m_architectureCount[ArchitectureFactory::instance().getArchitectureFromName(nameStr)] += valueNum;
	}

	return true;
}

bool HtmlGenerator::onEnd(const Glib::ustring& name)
{
	return true;
}

std::string HtmlGenerator::toXml()
{
	std::string out;

	out =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
			"<emilpro>\n"
			"  <HtmlGenerator>\n";

	for (CountryMap_t::iterator it = m_countryCount.begin();
			it != m_countryCount.end();
			++it) {
		std::string country = it->first;
		uint64_t count = it->second;

		out += fmt("    <CountryCount name=\"%s\">%llu</CountryCount>\n", country.c_str(), (unsigned long long)count);
	}
	for (ArchitectureMap_t::iterator it = m_architectureCount.begin();
			it != m_architectureCount.end();
			++it) {
		ArchitectureFactory::Architecture_t arch = it->first;
		uint64_t count = it->second;
		std::string name = ArchitectureFactory::instance().getNameFromArchitecture(arch);

		out += fmt("    <ArchitectureCount name=\"%s\">%llu</ArchitectureCount>\n", name.c_str(), (unsigned long long)count);
	}

	out +=  "  </HtmlGenerator>\n"
			"</emilpro>\n";

	return out;
}

std::string HtmlGenerator::produceHtml()
{
	std::map<uint64_t, std::list<std::string> > countriesByCount;
	std::map<uint64_t, std::list<ArchitectureFactory::Architecture_t> > archByCount;
	std::map<uint64_t, std::list<ArchitectureFactory::Architecture_t> > insnArchByCount;
	std::string out;

	for (CountryMap_t::iterator it = m_countryCount.begin();
			it != m_countryCount.end();
			++it) {
		std::string country = it->first;
		uint64_t count = it->second;

		countriesByCount[count].push_back(country);
	}

	for (ArchitectureMap_t::iterator it = m_architectureCount.begin();
			it != m_architectureCount.end();
			++it) {
		ArchitectureFactory::Architecture_t arch = it->first;
		uint64_t count = it->second;

		archByCount[count].push_back(arch);
	}

	for (ArchitectureMap_t::iterator it = m_instructionArchitectureCount.begin();
			it != m_instructionArchitectureCount.end();
			++it) {
		ArchitectureFactory::Architecture_t arch = it->first;
		uint64_t count = it->second;

		insnArchByCount[count].push_back(arch);
	}

	out =
			fmt("<html><body>\n"
			"<H2>EmilPRO network statistics</H2>\n"
			"The total number of connections is <b>%llu</b>.<br>\n"
			"<H3>Top countries</H3>\n",
			(unsigned long long)m_totalConnections);

	unsigned n = 1;
	for (std::map<uint64_t, std::list<std::string> >::reverse_iterator it = countriesByCount.rbegin();
			it != countriesByCount.rend();
			++it) {
		for (std::list<std::string>::iterator itLst = it->second.begin();
				itLst != it->second.end();
				++itLst) {
			std::string country = *itLst;
			uint64_t count = it->first;

			if (count == 0)
				break;

			if (n > 20)
				break;

			out += fmt("<tt>%2u</tt> %s (%llu)<br>\n", n, country.c_str(), (unsigned long long)count);

			n++;
		}
	}

	out += "<H3>Top disassembled architectures</H3>\n";

	n = 1;
	for (std::map<uint64_t, std::list<ArchitectureFactory::Architecture_t> >::reverse_iterator it = archByCount.rbegin();
			it != archByCount.rend();
			++it) {
		for (std::list<ArchitectureFactory::Architecture_t>::iterator itLst = it->second.begin();
				itLst != it->second.end();
				++itLst) {
			ArchitectureFactory::Architecture_t arch = *itLst;
			uint64_t count = it->first;
			std::string name = ArchitectureFactory::instance().getNameFromArchitecture(arch);

			if (count == 0)
				break;

			if (n > 10)
				break;

			out += fmt("<tt>%2u</tt> %s (%llu)<br>\n", n, name.c_str(), (unsigned long long)count);

			n++;
		}
	}

	out += "<H3>Instruction models per architecture</H3>\n";
	n = 1;
	for (std::map<uint64_t, std::list<ArchitectureFactory::Architecture_t> >::reverse_iterator it = insnArchByCount.rbegin();
			it != insnArchByCount.rend();
			++it) {
		for (std::list<ArchitectureFactory::Architecture_t>::iterator itLst = it->second.begin();
				itLst != it->second.end();
				++itLst) {
			ArchitectureFactory::Architecture_t arch = *itLst;
			uint64_t count = it->first;
			std::string name = ArchitectureFactory::instance().getNameFromArchitecture(arch);

			if (count == 0)
				break;

			if (n > 10)
				break;

			out += fmt("<tt>%-2u</tt> %s (%llu)<br>\n", n, name.c_str(), (unsigned long long)count);

			n++;
		}
	}

	out += "<H3>Last uploaded instructions</H3>\n";

	n = 1;
	for (TimestampToInsnMap_t::reverse_iterator it = m_lastInstructions.rbegin();
			it != m_lastInstructions.rend();
			++it) {
		uint64_t ts = it->first;
		std::string s = it->second;

		if (n > 10)
			break;

		out += fmt("<tt>%2u</tt> %s: %s<br>\n", n, s.c_str(), getNaturalTimeDiff(ts).c_str());

		n++;
	}


	out += "</body></html>\n";

	return out;
}

std::string emilpro::HtmlGenerator::getNaturalTimeDiff(uint64_t ts)
{
	uint64_t now = get_utc_timestamp();
	int64_t diff = now - ts;

	if (ts - now < 60)
		return "moments ago";

	if (diff < 60 * 60) {
		uint64_t minutes = diff / (60);

		return fmt("%llu minute%s ago", (unsigned long long)minutes, minutes == 1 ? "" : "s");
	}

	if (diff < 60 * 60 * 24) {
		uint64_t hours = diff / (60 * 60);

		return fmt("%llu hour%s ago", (unsigned long long)hours, hours == 1 ? "" : "s");
	}

	if (diff < 7 * 60 * 60 * 24) {
		uint64_t days = diff / (60 * 60 * 24);

		return fmt("%llu day%s ago", (unsigned long long)days, days == 1 ? "" : "s");
	}

	if (diff < 31 * 60 * 60 * 24) {
		uint64_t weeks = diff / (7 * 60 * 60 * 24);

		return fmt("%llu week%s ago", (unsigned long long)weeks, weeks == 1 ? "" : "s");
	}

	if (diff < 365 * 60 * 60 * 24) {
		uint64_t months = diff / (31 * 60 * 60 * 24);

		return fmt("%llu month%s ago", (unsigned long long)months, months == 1 ? "" : "s");
	}

	uint64_t years = diff / (365 * 60 * 60 * 24);

	return fmt("%llu year%s ago", (unsigned long long)years, years == 1 ? "" : "s");
}
