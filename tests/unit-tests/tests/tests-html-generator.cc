#include "../test.hh"

#include <utils.hh>
#include <configuration.hh>
#include <server/html-generator.hh>

#include <ctype.h>

using namespace emilpro;

static std::unordered_map<std::string, std::string> path_to_data;
static int write_callback(const void *data, size_t size, const char *path)
{
	path_to_data[path] = std::string((const char *)data);

	return 0;
}


TESTSUITE(html_generator)
{
	TEST(lookupCountries)
	{
		HtmlGenerator &gen = HtmlGenerator::instance();

		gen.addData("80.216.20.198", bfd_arch_i386);
		gen.addData("80.216.20.198", bfd_arch_i386);
		gen.addData("80.216.20.198", bfd_arch_i386);
		gen.addData("23.53.38.151", bfd_arch_sparc);
		gen.addData("202.248.194.70", bfd_arch_sparc);
		gen.addData("202.248.194.70", bfd_arch_unknown);


		mock_write_file(write_callback);
		gen.generate();
		std::string statsFilename = Configuration::instance().getPath(Configuration::DIR_SERVER_STATISTICS) + "/stats.html";
		std::string xmlFilename = Configuration::instance().getPath(Configuration::DIR_CONFIGURATION) + "/server-statistics.xml";

		ASSERT_TRUE(path_to_data[statsFilename].find("Sweden") != std::string::npos);
		ASSERT_TRUE(path_to_data[statsFilename].find("Japan") != std::string::npos);
		ASSERT_TRUE(path_to_data[statsFilename].find("United States") != std::string::npos);
		ASSERT_TRUE(path_to_data[xmlFilename].find("Sweden") != std::string::npos);
		ASSERT_TRUE(path_to_data[xmlFilename].find("Japan") != std::string::npos);
		ASSERT_TRUE(path_to_data[xmlFilename].find("United States") != std::string::npos);

		ASSERT_TRUE(gen.m_countryCount["Sweden"] == 3U);

		gen.destroy();
	}
}
