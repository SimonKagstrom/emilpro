#include "../test.hh"

#include <xmlfactory.hh>
#include <idisassembly.hh>

#include <utils.hh>

#include <stdlib.h>
#include <string>

using namespace emilpro;


static void *read_callback(size_t *out_size, const char *path)
{
	const char *out = "hej hopp";

	*out_size = strlen(out);

	return (void *)out;
}

static std::string write_data;
static int write_callback(const void *data, size_t size, const char *path)
{
	write_data = (const char *)data;

	return 5;
}

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

	TEST(adjustedTimestamp)
	{
		uint64_t before, after;

		before = get_utc_timestamp();
		adjust_utc_timestamp(-100000);
		after = get_utc_timestamp();
		ASSERT_TRUE(after < before);
	}

	TEST(mockRead)
	{
		size_t sz;
		void *p;

		p = read_file(&sz, "%s", "/etc/passwd");
		ASSERT_TRUE(p);
		ASSERT_TRUE(sz > 0U);
		std::string s = (const char *)p;

		ASSERT_TRUE(s.find("root") != std::string::npos);


		mock_read_file(read_callback);
		p = read_file(&sz, "%s", "/etc/passwd");
		ASSERT_TRUE(p);
		ASSERT_TRUE(sz == strlen("hej hopp"));
		s = (const char *)p;

		ASSERT_TRUE(s.find("root") == std::string::npos);
		ASSERT_TRUE(s.find("hej hopp") != std::string::npos);
	}

	TEST(mockWrite)
	{
		mock_write_file(write_callback);
		const char *data = "kalle anka";
		int res;

		res = write_file((const void *)data, strlen(data), "%s", "/tmp/kalle");
		ASSERT_TRUE(res == 5);
		ASSERT_TRUE(write_data == data);
	}

	TEST(realWrite)
	{
		std::string tmp = fmt("%s/kalle", crpcut::get_start_dir());

		const char *data = "arne anka";
		int rv;
		size_t sz;

		rv = write_file((const void *)data, strlen(data), "%s", tmp.c_str());
		char *p = (char *)read_file(&sz, "%s", tmp.c_str());

		unlink(tmp.c_str());

		ASSERT_TRUE(rv == 0);
		ASSERT_TRUE(sz == strlen(data));
		ASSERT_TRUE(strcmp(p, data) == 0);
		free(p);
	}
}
