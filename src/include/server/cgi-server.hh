#pragma once

#include <xmlfactory.hh>
#include <architecturefactory.hh>

#include <string>
#include <fstream>
#include <stdio.h>

namespace cgi_server
{
	class adjustTimestamp;
	class validRequest;
	class htmlGeneration;
}

namespace emilpro
{
	class CgiServer : public XmlFactory::IXmlListener
	{
	public:
		friend class cgi_server::adjustTimestamp;
		friend class cgi_server::validRequest;
		friend class cgi_server::htmlGeneration;

		CgiServer();

		~CgiServer();
		std::string reply();

		void request(const std::string xml);

	protected:
		// From IXmlListener
		bool onStart(const Glib::ustring &name, const xmlpp::SaxParser::AttributeList &properties, std::string value);

		bool onElement(const Glib::ustring &name, const xmlpp::SaxParser::AttributeList &properties, std::string value);

		bool onEnd(const Glib::ustring &name);

	private:
		uint64_t m_timestamp;
		int64_t m_timestampAdjustment;
		ArchitectureFactory::Architecture_t m_currentArchitecture;
		bool m_hasCurrentArchitecture;
		bool m_optOutFromStatistics;
	};

}
