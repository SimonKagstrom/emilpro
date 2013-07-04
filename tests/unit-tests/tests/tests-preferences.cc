#include "../test.hh"

#include <preferences.hh>
#include <xmlfactory.hh>

#include <string>
#include <unordered_map>

using namespace emilpro;

class PreferencesListener : public Preferences::IListener
{
public:
	std::unordered_map<std::string, std::string> m_oldValues;
	std::unordered_map<std::string, std::string> m_newValues;

private:
	void onPreferencesChanged(const std::string &key,
			const std::string &oldValue, const std::string &newValue)
	{
		m_oldValues[key] = oldValue;
		m_newValues[key] = newValue;
	}
};

TESTSUITE(preferences)
{
	TEST(registerBefore)
	{
		std::string xml =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				"<emilpro>\n"
				"  <Preferences>\n"
				"    <PreferenceEntry>\n"
				"       <PreferenceKey>color</PreferenceKey>\n"
				"       <PreferenceValue>127,63,241</PreferenceValue>\n"
				"    </PreferenceEntry>\n"
				"    <PreferenceEntry>\n"
				"       <PreferenceKey>ARNE</PreferenceKey>\n"
				"       <PreferenceValue>ANKA</PreferenceValue>\n"
				"    </PreferenceEntry>\n"
				"  </Preferences>\n"
				"</emilpro>\n"
				;

		Preferences &prefs = Preferences::instance();
		PreferencesListener listener;

		prefs.registerListener("color", &listener);
		ASSERT_TRUE(listener.m_newValues.find("ARNE") == listener.m_newValues.end());
		ASSERT_TRUE(listener.m_newValues.find("color") == listener.m_newValues.end());

		XmlFactory::instance().parse(xml);

		ASSERT_TRUE(listener.m_newValues.find("ARNE") == listener.m_newValues.end());
		ASSERT_TRUE(listener.m_newValues.find("color") != listener.m_newValues.end());
		ASSERT_TRUE(listener.m_oldValues.find("color") != listener.m_newValues.end());
		ASSERT_TRUE(listener.m_newValues["color"] == "127,63,241");

		prefs.unregisterListener(&listener);

		prefs.destroy();
	}


	TEST(registerAfter)
	{
		std::string xml =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				"<emilpro>\n"
				"  <Preferences>\n"
				"    <PreferenceEntry>\n"
				"       <PreferenceKey>color</PreferenceKey>\n"
				"       <PreferenceValue>127,63,241</PreferenceValue>\n"
				"    </PreferenceEntry>\n"
				"    <PreferenceEntry>\n"
				"       <PreferenceKey>ARNE</PreferenceKey>\n"
				"       <PreferenceValue>ANKA</PreferenceValue>\n"
				"    </PreferenceEntry>\n"
				"  </Preferences>\n"
				"</emilpro>\n"
				;

		Preferences &prefs = Preferences::instance();
		PreferencesListener listener;

		// Will fill in the preferences data
		XmlFactory::instance().parse(xml);
		prefs.registerListener("color", &listener);

		ASSERT_TRUE(listener.m_newValues.find("ARNE") == listener.m_newValues.end());
		ASSERT_TRUE(listener.m_newValues.find("color") != listener.m_newValues.end());
		ASSERT_TRUE(listener.m_oldValues.find("color") != listener.m_newValues.end());
		ASSERT_TRUE(listener.m_newValues["color"] == "127,63,241");

		prefs.unregisterListener(&listener);

		prefs.destroy();
	}

	TEST(unregisterListener)
	{
		std::string xml =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				"<emilpro>\n"
				"  <Preferences>\n"
				"    <PreferenceEntry>\n"
				"       <PreferenceKey>color</PreferenceKey>\n"
				"       <PreferenceValue>127,63,241</PreferenceValue>\n"
				"    </PreferenceEntry>\n"
				"    <PreferenceEntry>\n"
				"       <PreferenceKey>ARNE</PreferenceKey>\n"
				"       <PreferenceValue>ANKA</PreferenceValue>\n"
				"    </PreferenceEntry>\n"
				"  </Preferences>\n"
				"</emilpro>\n"
				;

		Preferences &prefs = Preferences::instance();
		PreferencesListener listener;

		prefs.registerListener("color", &listener);
		ASSERT_TRUE(listener.m_newValues.find("ARNE") == listener.m_newValues.end());
		ASSERT_TRUE(listener.m_newValues.find("color") == listener.m_newValues.end());

		prefs.unregisterListener(&listener);
		XmlFactory::instance().parse(xml);

		ASSERT_TRUE(listener.m_newValues.find("ARNE") == listener.m_newValues.end());
		ASSERT_TRUE(listener.m_newValues.find("color") == listener.m_newValues.end());

		prefs.destroy();
	}


	TEST(toXml)
	{
		std::string xml =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				"<emilpro>\n"
				"  <Preferences>\n"
				"    <PreferenceEntry>\n"
				"       <PreferenceKey>ARNE</PreferenceKey>\n"
				"       <PreferenceValue>ANKA</PreferenceValue>\n"
				"    </PreferenceEntry>\n"
				"    <PreferenceEntry>\n"
				"       <PreferenceKey>color</PreferenceKey>\n"
				"       <PreferenceValue>127,63,241</PreferenceValue>\n"
				"    </PreferenceEntry>\n"
				"  </Preferences>\n"
				"</emilpro>\n"
				;

		Preferences &prefs = Preferences::instance();

		std::string cmp;

		cmp = prefs.toXml();
		ASSERT_TRUE(cmp == "");

		XmlFactory::instance().parse(xml);

		cmp = prefs.toXml();

		ASSERT_TRUE(xml == cmp);
	}
}
