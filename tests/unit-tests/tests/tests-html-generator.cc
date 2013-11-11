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
		ASSERT_TRUE(gen.m_totalConnections == 7U);

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

		ASSERT_TRUE(path_to_data[statsFilename].find("connections is <b>7</b>") != std::string::npos);

		gen.destroy();
	}

	TEST(toAndFromXML)
	{
		HtmlGenerator &gen = HtmlGenerator::instance();

		gen.addData("80.216.20.198", bfd_arch_powerpc);
		gen.addData("80.216.20.198", bfd_arch_mips);
		gen.addData("80.216.20.198", bfd_arch_i386);
		gen.addData("23.53.38.151", bfd_arch_sparc);

		ASSERT_TRUE(gen.m_countryCount.size() == 2U);
		ASSERT_TRUE(gen.m_architectureCount.size() == 4U);

		std::string xml;

		xml = gen.toXml();

		gen.destroy();

		HtmlGenerator &gen2 = HtmlGenerator::instance();
		ASSERT_TRUE(gen2.m_countryCount.size() == 0U);
		ASSERT_TRUE(gen2.m_architectureCount.size() == 0U);

		bool res = XmlFactory::instance().parse(xml);
		ASSERT_TRUE(res);
		ASSERT_TRUE(gen2.m_countryCount.size() == 2U);
		ASSERT_TRUE(gen2.m_architectureCount.size() == 4U);
	}

	TEST(insnArchitecture)
	{
		std::string xml;

		xml =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
			"<emilpro>\n"
			"  <HtmlGenerator>\n"
			"    <CountryCount name=\"Sweden\">4</CountryCount>\n"
		    "    <ArchitectureCount name=\"z80\">4</ArchitectureCount>\n"
		    "    <TotalCount>4</TotalCount>\n"
			"  </HtmlGenerator>\n"
			"  <InstructionModel name=\"beqz\" architecture=\"mips\">\n"
			"  </InstructionModel>\n"
			"  <InstructionModel name=\"klabbarparn\" architecture=\"powerpc\">\n"
			"  </InstructionModel>\n"
			"  <InstructionModel name=\"eualia\" architecture=\"powerpc\">\n"
			"  </InstructionModel>\n"
			"</emilpro>\n";

		HtmlGenerator &gen = HtmlGenerator::instance();

		bool res = XmlFactory::instance().parse(xml);
		ASSERT_TRUE(res);
		ASSERT_TRUE(gen.m_countryCount.size() == 1U);
		ASSERT_TRUE(gen.m_architectureCount.size() == 1U);
		ASSERT_TRUE(gen.m_instructionArchitectureCount.size() == 2U);

		ASSERT_TRUE(gen.m_countryCount["Sweden"] == 4U);
		ASSERT_TRUE(gen.m_architectureCount[bfd_arch_z80] == 4U);

		ASSERT_TRUE(gen.m_instructionArchitectureCount[bfd_arch_mips] == 1U);
		ASSERT_TRUE(gen.m_instructionArchitectureCount[bfd_arch_powerpc] == 2U);

		xml = gen.toXml();

		gen.destroy();
	}

	TEST(loadStats)
	{
		std::string xml;

		xml =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				"<emilpro>\n"
				"  <HtmlGenerator>\n"
				"    <CountryCount name=\"Sweden\">1116</CountryCount>\n"
				"    <ArchitectureCount name=\"unknown\">127</ArchitectureCount>\n"
				"    <ArchitectureCount name=\"i386\">813</ArchitectureCount>\n"
				"    <ArchitectureCount name=\"powerpc\">64</ArchitectureCount>\n"
				"    <ArchitectureCount name=\"arm\">112</ArchitectureCount>\n"
				"  </HtmlGenerator>\n"
				"</emilpro>\n"
				;

		HtmlGenerator &gen = HtmlGenerator::instance();

		ASSERT_TRUE(gen.m_totalConnections == 0U);
		ASSERT_TRUE(gen.m_architectureCount[bfd_arch_i386] == 0U);

		bool res = XmlFactory::instance().parse(xml);
		ASSERT_TRUE(res);
		ASSERT_TRUE(gen.m_totalConnections == 1116U);
		ASSERT_TRUE(gen.m_architectureCount[bfd_arch_i386] == 813U);

		gen.addData("23.53.38.151", bfd_arch_sparc);
		ASSERT_TRUE(gen.m_totalConnections == 1117U);
	}

	TEST(naturalTimeDiff)
	{
		HtmlGenerator &gen = HtmlGenerator::instance();
#define MINUTES(n) (n * 60)
#define HOURS(n) (n * MINUTES(60))
#define DAYS(n) (n * HOURS(24))
#define WEEKS(n) (n * DAYS(7))
#define MONTHS(n) (n * DAYS(31))
#define YEARS(n) (n * MONTHS(12))

		std::string s;

		mock_utc_timestamp(0);
		s = gen.getNaturalTimeDiff(0);
		ASSERT_TRUE(s == "moments ago");

		mock_utc_timestamp(MINUTES(5));
		s = gen.getNaturalTimeDiff(0);
		ASSERT_TRUE(s == "5 minutes ago");

		mock_utc_timestamp(MINUTES(1));
		s = gen.getNaturalTimeDiff(0);
		ASSERT_TRUE(s == "1 minute ago");

		mock_utc_timestamp(HOURS(23));
		s = gen.getNaturalTimeDiff(0);
		ASSERT_TRUE(s == "23 hours ago");

		mock_utc_timestamp(DAYS(5));
		s = gen.getNaturalTimeDiff(0);
		ASSERT_TRUE(s == "5 days ago");

		mock_utc_timestamp(WEEKS(3));
		s = gen.getNaturalTimeDiff(0);
		ASSERT_TRUE(s == "3 weeks ago");

		mock_utc_timestamp(MONTHS(1));
		s = gen.getNaturalTimeDiff(0);
		ASSERT_TRUE(s == "1 month ago");

		mock_utc_timestamp(YEARS(2));
		s = gen.getNaturalTimeDiff(0);
		ASSERT_TRUE(s == "2 years ago");

		gen.destroy();
	}
}
