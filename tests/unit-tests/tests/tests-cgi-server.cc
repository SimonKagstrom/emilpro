#include "../test.hh"

#include <utils.hh>
#include "../../../src/server/cgi-server.cc"
#include <configuration.hh>

#include <ctype.h>

static std::unordered_map<std::string, std::string> path_to_data;
static int write_callback(const void *data, size_t size, const char *path)
{
	path_to_data[path] = std::string((const char *)data);

	return 0;
}

class ServerFixture
{
public:
	ServerFixture()
	{
		// Avoid loading current statistics, conf etc
		Configuration::instance().setBaseDirectory("/this/beautiful/creature");

		mock_write_file(write_callback);
	}
};

TESTSUITE(cgi_server)
{
	TEST(brokenXML, ServerFixture)
	{
		CgiServer server;
		std::string reply;
		std::string xml;

		server.request("Leif GW Persson");

		reply = server.reply();
		ASSERT_TRUE(reply == "");

		xml =   "  <ServerTimestamps>\n"
				"    <InstructionModelTimestamp>1</InstructionModelTimestamp>\n"
				"  </ServerTimestampsXXX>\n";
		server.request(xml);

		reply = server.reply();
		ASSERT_TRUE(reply == "");

		xml =   "  <ServerTimestamps>\n"
				"    <vobb>1</vobb>\n"
				"  </ServerTimestamps>\n";
		server.request(xml);

		reply = server.reply();
		ASSERT_TRUE(reply == "");
	}

	TEST(validRequest, ServerFixture)
	{
		CgiServer server;
		std::string reply;
		std::string xml;

		xml =   "  <ServerTimestamps>\n"
				"    <InstructionModelTimestamp>1</InstructionModelTimestamp>\n"
				"  </ServerTimestamps>\n";
		server.request(xml);
		ASSERT_TRUE(server.m_currentArchitecture == bfd_arch_unknown);

		reply = server.reply();
		ASSERT_TRUE(reply != "");

		std::string insns =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				"<emilpro>\n"
				"  <InstructionModel name=\"beqz\" architecture=\"mips\" timestamp=\"1\">\n"
				"    <type>cflow</type>\n"
				"  </InstructionModel>\n"
				"  <InstructionModel name=\"sub\" architecture=\"mips\" timestamp=\"3\">\n"
				"    <type>data_handling</type>\n"
				"  </InstructionModel>\n"
				"  <InstructionModel name=\"addiu\" architecture=\"mips\" timestamp=\"5\">\n"
				"    <type>other</type>\n"
				"  </InstructionModel>\n"
				"</emilpro>\n";

		bool res = XmlFactory::instance().parse(insns);
		ASSERT_TRUE(res);

		xml =   "  <ServerTimestamps>\n"
				"    <InstructionModelTimestamp>1</InstructionModelTimestamp>\n"
				"    <CurrentArchitecture>powerpc</CurrentArchitecture>\n"
				"    <KalleAnka>Satt pa en planka</KalleAnka>\n"
				"  </ServerTimestamps>\n";
		server.request(xml);
		ASSERT_TRUE(server.m_currentArchitecture == bfd_arch_powerpc);

		reply = server.reply();
		ASSERT_TRUE(reply != "");

		ASSERT_TRUE(reply.find("beqz") == std::string::npos);
		ASSERT_TRUE(reply.find("sub") != std::string::npos);
		ASSERT_TRUE(reply.find("addiu") != std::string::npos);


		xml =   "  <ServerTimestamps>\n"
				"    <InstructionModelTimestamp>5</InstructionModelTimestamp>\n"
				"  </ServerTimestamps>\n";
		server.request(xml);

		reply = server.reply();
		ASSERT_TRUE(reply != "");
		ASSERT_TRUE(reply.find("beqz") == std::string::npos);
		ASSERT_TRUE(reply.find("sub") == std::string::npos);
		ASSERT_TRUE(reply.find("addiu") == std::string::npos);


		xml =   "  <ServerTimestamps>\n"
				"    <InstructionModelTimestamp>4</InstructionModelTimestamp>\n"
				"  </ServerTimestamps>\n";
		server.request(xml);

		reply = server.reply();
		ASSERT_TRUE(reply != "");
		ASSERT_TRUE(reply.find("beqz") == std::string::npos);
		ASSERT_TRUE(reply.find("sub") == std::string::npos);
		ASSERT_TRUE(reply.find("addiu") != std::string::npos);
	}

	TEST(adjustTimestamp, ServerFixture)
	{
		CgiServer server;
		std::string reply;
		std::string xml;

		xml = fmt(
				"  <ServerTimestamps>\n"
				"    <InstructionModelTimestamp>1</InstructionModelTimestamp>\n"
				"  </ServerTimestamps>\n"
				);
		server.request(xml);

		reply = server.reply();
		ASSERT_TRUE(reply != "");
		ASSERT_TRUE(server.m_timestampAdjustment == 0);

		xml = fmt(
				"  <ServerTimestamps>\n"
				"    <InstructionModelTimestamp>1</InstructionModelTimestamp>\n"
				"    <Timestamp>%llu</Timestamp>"
				"  </ServerTimestamps>\n",
				(unsigned long long)get_utc_timestamp() - 1000 // Simulate time difference
				);
		server.request(xml);

		reply = server.reply();
		ASSERT_TRUE(reply != "");
		ASSERT_TRUE(server.m_timestampAdjustment > 0);


		xml = fmt(
				"  <ServerTimestamps>\n"
				"    <InstructionModelTimestamp>1</InstructionModelTimestamp>\n"
				"    <Timestamp>%llu</Timestamp>"
				"  </ServerTimestamps>\n",
				(unsigned long long)get_utc_timestamp() + 1000
				);
		server.request(xml);

		reply = server.reply();
		ASSERT_TRUE(reply != "");
		ASSERT_TRUE(server.m_timestampAdjustment < 0);
	}

	TEST(htmlGeneration, ServerFixture)
	{
		CgiServer server;
		std::string reply;
		std::string xml;
		std::string statsFilename = Configuration::instance().getPath(Configuration::DIR_SERVER_STATISTICS) + "/stats.html";

		setenv("REMOTE_ADDR", "202.248.194.70", 1);
		xml =   "  <ServerTimestamps>\n"
				"    <InstructionModelTimestamp>1</InstructionModelTimestamp>\n"
				"    <CurrentArchitecture>z80</CurrentArchitecture>\n"
				"  </ServerTimestamps>\n";
		server.request(xml);
		ASSERT_TRUE(server.m_currentArchitecture == bfd_arch_z80);

		reply = server.reply();
		ASSERT_TRUE(reply != "");

		xml =   "  <ServerTimestamps>\n"
				"    <InstructionModelTimestamp>1</InstructionModelTimestamp>\n"
				"    <CurrentArchitecture>m68k</CurrentArchitecture>\n"
				"  </ServerTimestamps>\n";
		server.request(xml);
		ASSERT_TRUE(server.m_currentArchitecture == bfd_arch_m68k);

		reply = server.reply();
		ASSERT_TRUE(reply != "");


		ASSERT_TRUE(path_to_data[statsFilename].find("z80 (1)") != std::string::npos);
		ASSERT_TRUE(path_to_data[statsFilename].find("m68k (1)") != std::string::npos);
		ASSERT_TRUE(path_to_data[statsFilename].find("Japan (2)") != std::string::npos);

		reply = server.reply();
		ASSERT_TRUE(reply != "");

		// No CurrentArchitectures
		xml =   "  <ServerTimestamps>\n"
				"    <InstructionModelTimestamp>1</InstructionModelTimestamp>\n"
				"  </ServerTimestamps>\n";
		server.request(xml);
		ASSERT_TRUE(path_to_data[statsFilename].find("Japan (2)") != std::string::npos);

		// Opt out
		xml =   "  <ServerTimestamps optOutFromStatistics=\"yes\">\n"
				"    <InstructionModelTimestamp>1</InstructionModelTimestamp>\n"
				"    <CurrentArchitecture>m68k</CurrentArchitecture>\n"
				"  </ServerTimestamps>\n";
		server.request(xml);
		ASSERT_TRUE(path_to_data[statsFilename].find("Japan (2)") != std::string::npos);

		// Opt in
		xml =   "  <ServerTimestamps optOutFromStatistics=\"no\">\n"
				"    <InstructionModelTimestamp>1</InstructionModelTimestamp>\n"
				"    <CurrentArchitecture>m68k</CurrentArchitecture>\n"
				"  </ServerTimestamps>\n";
		server.request(xml);
		ASSERT_TRUE(path_to_data[statsFilename].find("Japan (3)") != std::string::npos);
	}
}
