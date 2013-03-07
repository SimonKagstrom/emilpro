#pragma once

#include <libxml++/libxml++.h>

#include <list>
#include <unordered_map>

namespace emilpro
{
	class XmlFactory : public xmlpp::SaxParser
	{
	public:
		class IXmlListener
		{
		public:
			virtual ~IXmlListener()
			{
			}

			virtual bool onStart(const Glib::ustring &name, const xmlpp::SaxParser::AttributeList &properties, std::string value) = 0;

			virtual bool onElement(const Glib::ustring &name, const xmlpp::SaxParser::AttributeList &properties, std::string value) = 0;

			virtual bool onEnd(const Glib::ustring &name) = 0;


			void setName(std::string &name)
			{
				m_name = name;
			}

			std::string m_name;
		};


		XmlFactory();

		virtual ~XmlFactory();

		void destroy();

		bool parse(std::string str);

		bool parseFile(std::string fileName);


		void registerListener(std::string elementName, IXmlListener *listener);


		static XmlFactory &instance();

	protected:
		//overrides:
		virtual void on_start_document();
		virtual void on_end_document();
		virtual void on_start_element(const Glib::ustring& name,
				const AttributeList& properties);
		virtual void on_end_element(const Glib::ustring& name);
		virtual void on_characters(const Glib::ustring& characters);
		virtual void on_comment(const Glib::ustring& text);
		virtual void on_warning(const Glib::ustring& text);
		virtual void on_error(const Glib::ustring& text);
		virtual void on_fatal_error(const Glib::ustring& text);

	private:
		typedef std::list<IXmlListener *> ListenerList_t;
		typedef std::list<ListenerList_t *> ListenerStack_t;

		typedef std::unordered_map<std::string, ListenerList_t> ElementToListenerMap_t;

		void maybePopListener(const Glib::ustring& name);

		ElementToListenerMap_t m_elementListeners;
		ListenerStack_t m_listenerStack;

		bool m_validationRun;
		Glib::ustring m_currentName;
		AttributeList m_currentProperties;
	};
}
