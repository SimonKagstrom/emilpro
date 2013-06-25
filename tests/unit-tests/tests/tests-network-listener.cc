#include "../test.hh"

#include <xmlfactory.hh>
#include <network-listener.hh>
#include <configuration.hh>

#include <utils.hh>
#include <string>
#include <list>
#include <unordered_map>

using namespace emilpro;

static std::unordered_map<std::string, std::string> path_to_data;

static int write_callback(const void *data, size_t size, const char *path)
{
	path_to_data[path] = std::string((const char *)data);

	return 0;
}


TESTSUITE(network_listener)
{
	TEST(parseInvalid)
	{
		std::string xml =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				"<emilpro>\n"
				"  <InstructionModel name=\"bge\" architecture=\"mips\">\n"
				"    <type>cflow</type>\n"
				"  </InstructionModel>\n"
				"  <InstructionModel name=\"addiu\" architecture=\"mips\">\n"
				"    <type>arithmetic_logic</type>\n"
				"  </InstructionModel>\n"
				"</emilprod>\n"; // Error here

		mock_write_file(write_callback);

		NetworkListener nl;
		XmlFactory::instance().parse(xml, true);

		ASSERT_TRUE(path_to_data.size() == 0U);
	}

	TEST(parse)
	{
		std::string xml =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				"<emilpro>\n"
				"  <InstructionModel name=\"bge\" architecture=\"mips\">\n"
				"    <type>cflow</type>\n"
				"  </InstructionModel>\n"
				"  <InstructionModel name=\"addiu\" architecture=\"mips\">\n"
				"    <type>arithmetic_logic</type>\n"
				"  </InstructionModel>\n"
				"</emilpro>\n";

		mock_write_file(write_callback);

		NetworkListener nl;
		XmlFactory::instance().parse(xml, true);

		ASSERT_TRUE(path_to_data.size() == 2U);

		Configuration &conf = Configuration::instance();
		std::string remoteDir = conf.getPath(Configuration::DIR_REMOTE);

		std::string bge = path_to_data[fmt("%s/mips/bge.xml", remoteDir.c_str())];
		std::string addiu = path_to_data[fmt("%s/mips/addiu.xml", remoteDir.c_str())];

		ASSERT_TRUE(bge.find("cflow") != std::string::npos);
		ASSERT_TRUE(addiu.find("arithmetic_logic") != std::string::npos);
		ASSERT_TRUE(addiu.find("cflow") == std::string::npos);
	}
}
