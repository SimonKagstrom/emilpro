#include "../test.hh"

#include <xmlfactory.hh>
#include <idisassembly.hh>

#include <utils.hh>

#include <stdlib.h>

using namespace emilpro;

TESTSUITE(utils)
{
	TEST(timestamp, DEADLINE_REALTIME_MS(2500))
	{
		uint64_t before, after;

		before = get_utc_timestamp();
		sleep(2);
		after = get_utc_timestamp();
		ASSERT_TRUE(after > before);
	}
}
