#include "../test.hh"

#include <utils.hh>
#include "../../../src/server/cgi-server.cc"

#include <ctype.h>

TESTSUITE(cgi_server)
{
	TEST(brokenXML)
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

	TEST(validRequest)
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

	TEST(adjustTimestamp)
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
}
