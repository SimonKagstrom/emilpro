#include "../test.hh"

#include <xmlfactory.hh>
#include <network-listener.hh>
#include <configuration.hh>
#include <instructionfactory.hh>

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

	TEST(parseEmptyDescr)
	{
		std::string xml =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				"<emilpro>\n"
				"  <InstructionModel name=\"sub\" architecture=\"mips\" timestamp=\"1\">\n"
				"    <type>data_handling</type>\n"
				"    <privileged>unknown</privileged>\n"
				"    <description></description>\n"
				"  </InstructionModel>\n"
				"</emilpro>\n";
		bool res;

		mock_write_file(write_callback);

		NetworkListener nl;
		res = XmlFactory::instance().parse(xml, true);
		ASSERT_TRUE(res);

		ASSERT_TRUE(path_to_data.size() == 1U);

		Configuration &conf = Configuration::instance();
		std::string remoteDir = conf.getPath(Configuration::DIR_REMOTE);

		std::string sub = path_to_data[fmt("%s/mips/sub.xml", remoteDir.c_str())];

		// Create the instruction factory
		InstructionFactory &insnFact = InstructionFactory::instance();

		res = XmlFactory::instance().parse(sub);
		ASSERT_TRUE(res);

		InstructionFactory::InstructionModelList_t lst = insnFact.getInstructionModels(1);
		ASSERT_TRUE(lst.size() == 1);
		InstructionFactory::IInstructionModel *model = lst.front();
		ASSERT_TRUE(model->getDescription() == "");
		ASSERT_TRUE(model->getType() == IInstruction::IT_DATA_HANDLING);
	}
}
