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
		gen.addData("", bfd_arch_mips); // Environment not set


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
		ASSERT_TRUE(path_to_data[xmlFilename].find("Unknown") != std::string::npos);

		ASSERT_TRUE(gen.m_countryCount["Sweden"] == 3U);

		// Test that the output HTML is ordered
		size_t swePos = path_to_data[statsFilename].find("1</b>. Sweden (3)");
		size_t japanPos = path_to_data[statsFilename].find("2</b>. Japan (2)");

		ASSERT_TRUE(swePos != std::string::npos);
		ASSERT_TRUE(japanPos != std::string::npos);
		ASSERT_TRUE(swePos < japanPos);

		size_t i386Pos = path_to_data[statsFilename].find("1</b>. i386 (3)");
		size_t sparcPos = path_to_data[statsFilename].find("2</b>. sparc (2)");

		ASSERT_TRUE(i386Pos != std::string::npos);
		ASSERT_TRUE(sparcPos != std::string::npos);
		ASSERT_TRUE(i386Pos < sparcPos);

		gen.destroy();
	}
}
