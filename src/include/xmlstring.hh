#pragma once

#include <xmlfactory.hh>

#include <string>

namespace emilpro
{
	class XmlString : public XmlFactory::IXmlListener
	{
	public:
		XmlString(const std::string &tag);

		~XmlString();

		/**
		 * Returns the XML representation of the currently parsed stuff
		 *
		 * @return the textual XML
		 */
		std::string getString();

		void clear();

	private:
		virtual bool onStart(const Glib::ustring &name, const xmlpp::SaxParser::AttributeList &properties, std::string value);

		virtual bool onElement(const Glib::ustring &name, const xmlpp::SaxParser::AttributeList &properties, std::string value);

		virtual bool onEnd(const Glib::ustring &name);


		std::string handleProperties(const xmlpp::SaxParser::AttributeList &properties);

		void indent();


		unsigned m_level;
		std::string m_string;
		const std::string m_tag;
	};
}
