#pragma once

#include <libxml++/libxml++.h>

#include <list>
#include <unordered_map>
#include <mutex>

// unit test stuff
namespace xmlfactory
{
	class unregisterMultipleListeners;
}

namespace emilpro
{
	class XmlFactory : public xmlpp::SaxParser
	{
	public:
		friend class xmlfactory::unregisterMultipleListeners;

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
				m_names.push_back(name);
			}

			bool hasName(const std::string &name)
			{
				for (std::list<std::string>::iterator it = m_names.begin();
						it != m_names.end();
						++it) {
					if (name == *it)
						return true;
				}

				return false;
			}

			std::list<std::string > m_names;
		};


		XmlFactory();

		virtual ~XmlFactory();

		void destroy();


		bool isParsingRemoteData();


		bool parse(const std::string str, bool isRemote = false);

		void registerListener(std::string elementName, IXmlListener *listener, bool prioritized = false);

		void unregisterListener(IXmlListener *listener);


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
		void unregisterListenerName(IXmlListener *listener, const std::string &name);

		ElementToListenerMap_t m_elementListeners;
		ListenerStack_t m_listenerStack;

		bool m_validationRun;
		Glib::ustring m_currentName;
		AttributeList m_currentProperties;

		bool m_isRemote;
		std::mutex m_mutex;
	};
}
