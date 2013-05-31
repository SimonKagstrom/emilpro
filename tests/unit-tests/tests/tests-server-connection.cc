#include "../test.hh"

#include <utils.hh>
#include <list>
#include <string>

#include "../../../src/server-connection.cc"

class MockConnectionHandler : public Server::IConnectionHandler
{
public:
	MockConnectionHandler() :
		m_setupResult(true)
	{
	}

	bool setup(void)
	{
		return m_setupResult;
	}

	std::string talk(const std::string &xml)
	{
		m_talkRequests.push_back(xml);

		if (m_talkResults.empty())
			return "";

		std::string out = m_talkResults.front();
		m_talkResults.pop_front();

		return out;
	}

	void clear()
	{
		m_talkRequests.clear();
		m_talkResults.clear();
	}

	bool m_setupResult;
	std::list<std::string> m_talkRequests;
	std::list<std::string> m_talkResults;
};

TESTSUITE(server_connection)
{
	TEST(connect)
	{
		MockConnectionHandler *ch = new MockConnectionHandler();
		Server &server = Server::instance();
		bool res;

		server.setConnectionHandler(*ch);

		ch->m_setupResult = false;
		res = server.connect();
		ASSERT_TRUE(res == false);

		ASSERT_TRUE(ch->m_talkRequests.size() == 0U);

		ch->m_setupResult = true;
		res = server.connect();
		ASSERT_TRUE(res == true);
		server.stop();

		// Only timestamp sent
		ASSERT_TRUE(ch->m_talkRequests.size() == 1U);
		ch->clear();

		server.destroy();
	}

	TEST(serverTimestampReply)
	{
		MockConnectionHandler *ch = new MockConnectionHandler();
		Server &server = Server::instance();
		bool res;

		server.setConnectionHandler(*ch);

		std::string xml =
				"  <ServerTimestamps>\n"
				"    <ServerTimestampDiff>-10000</ServerTimestampDiff>\n"
				"  </ServerTimestamps>\n"
				;

		ch->m_talkResults.push_back(xml);

		uint64_t before = get_utc_timestamp();
		res = server.connect();
		ASSERT_TRUE(res == true);
		server.stop();
		uint64_t after = get_utc_timestamp();

		ASSERT_TRUE(ch->m_talkRequests.size() == 1U);
		ASSERT_TRUE(after < before);

		ch->clear();

		xml =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				"<emilpro>\n"
				"  <ServerTimestamps>\n"
				"    <ServerTimestampDiff>-10000</ServerTimestampDiff>\n"
				"  </ServerTimestamps>\n"
				"</emilpro>\n"
				;

		ch->m_talkResults.push_back(xml);
		res = server.connect();
		ASSERT_TRUE(res == true);
		server.stop();
		uint64_t after2 = get_utc_timestamp();

		ASSERT_TRUE(ch->m_talkRequests.size() == 1U);
		ASSERT_TRUE(after2 < after);

		server.destroy();
	}

	TEST(serverModelReply)
	{
		MockConnectionHandler *ch = new MockConnectionHandler();
		Server &server = Server::instance();
		bool res;

		server.setConnectionHandler(*ch);

		std::string xml;
		InstructionFactory &factory = InstructionFactory::instance();

		ASSERT_TRUE(factory.getInstructionModels(0).size() == 0U);
		xml =
				fmt(
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				"<emilpro>\n"
				"  <InstructionModel name=\"beqz\" architecture=\"mips\" timestamp=\"%llu\">\n"
				"    <type>cflow</type>\n"
				"  </InstructionModel>\n"
				"  <InstructionModel name=\"sub\" architecture=\"mips\" timestamp=\"%llu\">\n"
				"    <type>data_handling</type>\n"
				"  </InstructionModel>\n"
				"</emilpro>\n",
				(unsigned long long)get_utc_timestamp(), (unsigned long long)get_utc_timestamp())
				;

		ch->m_talkResults.push_back(xml);
		res = server.connect();
		ASSERT_TRUE(res == true);
		server.stop();
		ASSERT_TRUE(ch->m_talkRequests.size() == 1U);
		ASSERT_TRUE(factory.getInstructionModels(0).size() == 2U);

		server.destroy();
	}
}
