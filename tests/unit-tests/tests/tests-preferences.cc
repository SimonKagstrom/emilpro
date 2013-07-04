#include "../test.hh"

#include <preferences.hh>
#include <configuration.hh>
#include <xmlfactory.hh>
#include <utils.hh>

#include <string>
#include <unordered_map>

using namespace emilpro;

static std::unordered_map<std::string, std::string> path_to_data;

static int write_callback(const void *data, size_t size, const char *path)
{
	path_to_data[path] = std::string((const char *)data);

	return size;
}

class PreferencesFixture
{
public:
	PreferencesFixture()
	{
		mock_write_file(write_callback);
	}
};

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
	TEST(registerBefore, PreferencesFixture)
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


	TEST(registerAfter, PreferencesFixture)
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

	TEST(unregisterListener, PreferencesFixture)
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


	TEST(toXml, PreferencesFixture)
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

	TEST(writeOnSet, PreferencesFixture)
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
		std::string xmlAfter =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				"<emilpro>\n"
				"  <Preferences>\n"
				"    <PreferenceEntry>\n"
				"       <PreferenceKey>ARNE</PreferenceKey>\n"
				"       <PreferenceValue>TAMMER</PreferenceValue>\n"
				"    </PreferenceEntry>\n"
				"    <PreferenceEntry>\n"
				"       <PreferenceKey>color</PreferenceKey>\n"
				"       <PreferenceValue>127,63,241</PreferenceValue>\n"
				"    </PreferenceEntry>\n"
				"  </Preferences>\n"
				"</emilpro>\n"
				;

		Preferences &prefs = Preferences::instance();

		XmlFactory::instance().parse(xml);

		prefs.setValue("ARNE", "TAMMER");

		ASSERT_TRUE(path_to_data[Configuration::instance().getPath(Configuration::DIR_CONFIGURATION) + "/preferences.xml"] == xmlAfter);
	}
}
