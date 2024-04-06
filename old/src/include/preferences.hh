#pragma once

#include <xmlfactory.hh>

#include <string>
#include <list>
#include <unordered_map>
#include <map>

// unit test stuff
namespace preferences
{
	class toXml;
}

namespace emilpro
{
	class Preferences : public XmlFactory::IXmlListener
	{
	public:
		friend class preferences::toXml;

		class IListener
		{
		public:
			virtual ~IListener()
			{
			}

			virtual void onPreferencesChanged(const std::string &key,
					const std::string &oldValue, const std::string &newValue) = 0;
		};

		void registerListener(const std::string &key, IListener *listener);

		void unregisterListener(IListener *listener);

		void setValue(const std::string &key, const std::string &value);


		void destroy();

		static Preferences &instance();

	private:
		Preferences();

		~Preferences();

		std::string toXml();

		virtual bool onStart(const Glib::ustring &name, const xmlpp::SaxParser::AttributeList &properties, std::string value);

		virtual bool onElement(const Glib::ustring &name, const xmlpp::SaxParser::AttributeList &properties, std::string value);

		virtual bool onEnd(const Glib::ustring &name);


		typedef std::list<IListener *> ListenerList_t;
		typedef std::unordered_map<std::string, ListenerList_t> ListenerMap_t;
		typedef std::map<std::string, std::string> KeyValueMap_t;

		ListenerMap_t m_listeners;
		KeyValueMap_t m_values;

		std::string m_curKey;
		std::string m_curValue;
	};
}
