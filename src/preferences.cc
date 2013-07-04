#include <preferences.hh>
#include <xmlfactory.hh>

using namespace emilpro;

class DiskPreferences : public XmlFactory::IXmlListener
{
public:
};


void Preferences::registerListener(const std::string& key,
		IListener* listener)
{
	// FIXME! Don't allow registering one listener multiple times...

	m_listeners[key].push_back(listener);

	if (m_values.find(key) != m_values.end())
		listener->onPreferencesChanged(key, m_values[key], m_values[key]);
}

void Preferences::unregisterListener(IListener* listener)
{
	for (Preferences::ListenerMap_t::iterator it = m_listeners.begin();
			it != m_listeners.end();
			++it) {
		Preferences::ListenerList_t &cur = it->second;
		Preferences::ListenerList_t::iterator foundIt = cur.end();

		for (Preferences::ListenerList_t::iterator lIt = cur.begin();
				lIt != cur.end();
				++lIt) {
			Preferences::IListener *p = *lIt;

			if (p == listener)
				foundIt = lIt;
		}

		if (foundIt != cur.end())
			cur.erase(foundIt);
	}

	// FIXME! Implement
	//m_listeners.erase(listener);
}

void Preferences::setValue(const std::string& key,
		const std::string& value)
{
	std::string old = m_values[key];

	m_values[key] = value;

	Preferences::ListenerList_t lst = m_listeners[key];

	for (Preferences::ListenerList_t::iterator it = lst.begin();
			it != lst.end();
			++it) {
		Preferences::IListener *p = *it;

		p->onPreferencesChanged(key, old, value);
	}
}

bool Preferences::onStart(const Glib::ustring &name,
		const xmlpp::SaxParser::AttributeList &properties, std::string value)
{
	return true;
}

bool Preferences::onElement(const Glib::ustring &name,
		const xmlpp::SaxParser::AttributeList &properties, std::string value)
{
	if (name == "PreferenceKey") {
		m_curKey = value;
	} else if (name == "PreferenceValue") {
		m_curValue = value;

		setValue(m_curKey, m_curValue);

		m_curKey.clear();
		m_curValue.clear();
	}

	return true;
}

bool Preferences::onEnd(const Glib::ustring &name)
{
	return true;
}

std::string Preferences::toXml()
{
	if (m_values.size() == 0)
		return "";

	std::string out =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
			"<emilpro>\n"
			"  <Preferences>\n";

	for (Preferences::KeyValueMap_t::iterator it = m_values.begin();
			it != m_values.end();
			++it) {
		std::string key = it->first;
		std::string value = it->second;

		out +=
				"    <PreferenceEntry>\n"
				"       <PreferenceKey>" + key + "</PreferenceKey>\n"
				"       <PreferenceValue>" + value + "</PreferenceValue>\n"
				"    </PreferenceEntry>\n";
	}

	out +=
			"  </Preferences>\n"
			"</emilpro>\n";

	return out;
}

static Preferences *g_instance;

void Preferences::destroy()
{
	g_instance = NULL;

	delete this;
}

Preferences& Preferences::instance()
{
	if (!g_instance)
		g_instance = new Preferences();

	return *g_instance;
}

Preferences::Preferences()
{
	XmlFactory::instance().registerListener("Preferences", this);
}

Preferences::~Preferences()
{
	XmlFactory::instance().unregisterListener(this);
}
