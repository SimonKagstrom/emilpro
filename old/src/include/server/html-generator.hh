#pragma once

#include <architecturefactory.hh>
#include <xmlfactory.hh>
#include <GeoIP.h>

#include <map>
#include <string>

// Unit test
namespace html_generator
{
	class lookupCountries;
	class toAndFromXML;
	class insnArchitecture;
	class loadStats;
	class naturalTimeDiff;
}

namespace emilpro
{
	class HtmlGenerator : public XmlFactory::IXmlListener
	{
	public:
		friend class html_generator::lookupCountries;
		friend class html_generator::toAndFromXML;
		friend class html_generator::insnArchitecture;
		friend class html_generator::loadStats;
		friend class html_generator::naturalTimeDiff;


		void addData(const char *ip, ArchitectureFactory::Architecture_t arch);

		void generate();

		void destroy();


		static HtmlGenerator &instance();

	private:
		typedef std::map<std::string, uint64_t> CountryMap_t;
		typedef std::map<ArchitectureFactory::Architecture_t, uint64_t> ArchitectureMap_t;
		typedef std::map<uint64_t, std::string> TimestampToInsnMap_t;

		HtmlGenerator();

		~HtmlGenerator();

		// From XmlFactory
		virtual bool onStart(const Glib::ustring &name, const xmlpp::SaxParser::AttributeList &properties, std::string value);
		virtual bool onElement(const Glib::ustring &name, const xmlpp::SaxParser::AttributeList &properties, std::string value);
		virtual bool onEnd(const Glib::ustring &name);

		std::string toXml();

		std::string produceHtml();

		std::string getNaturalTimeDiff(uint64_t ts);

		GeoIP *m_gip;
		uint64_t m_totalConnections;
		CountryMap_t m_countryCount;
		ArchitectureMap_t m_architectureCount;
		ArchitectureMap_t m_instructionArchitectureCount;
		TimestampToInsnMap_t m_lastInstructions;
	};
}
