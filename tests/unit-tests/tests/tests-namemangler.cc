#include "../test.hh"

#include <namemangler.hh>

using namespace emilpro;

TESTSUITE(namemangler)
{
	TEST(unmangleableNames)
	{
		ASSERT_SCOPE_HEAP_LEAK_FREE
		{
			NameMangler &m = NameMangler::instance();

			std::string res;

			res = m.mangle("");
			ASSERT_TRUE(res == "");

			res = m.mangle("bruce lee");
			ASSERT_TRUE(res == "bruce lee");

			res = m.mangle("ghosts n' goblins");
			ASSERT_TRUE(res == "ghosts n' goblins");

			// Almost OK
			res = m.mangle("ZN2ai14MockEvaluateAiC2Ev");
			ASSERT_TRUE(res == "ZN2ai14MockEvaluateAiC2Ev");

			m.destroy();
			Preferences::instance().destroy();
			XmlFactory::instance().destroy();
		}
	}

	TEST(mangleableNames)
	{
		ASSERT_SCOPE_HEAP_LEAK_FREE
		{
			NameMangler &m = NameMangler::instance();

			std::string res;

			res = m.mangle("_ZN2ai14MockEvaluateAiC2Ev");
			ASSERT_TRUE(res == "ai::MockEvaluateAi::MockEvaluateAi()");

			m.destroy();
			Preferences::instance().destroy();
			XmlFactory::instance().destroy();
		}
	}
}
