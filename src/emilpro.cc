#include <emilpro.hh>
#include <model.hh>
#include <architecturefactory.hh>
#include <symbolfactory.hh>
#include <instructionfactory.hh>
#include <idisassembly.hh>
#include <xmlfactory.hh>
#include <configuration.hh>
#include <server.hh>
#include <utils.hh>
#include <preferences.hh>
#include <namemangler.hh>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>

#include <built_in_instruction_models.hh>

using namespace emilpro;

static EmilPro *g_instance;

void EmilPro::init()
{
	panic_if(g_instance,
			"Instance already created");

	g_instance = new EmilPro();

	// Create everything
	Configuration &conf = Configuration::instance();
	Model::instance();
	SymbolFactory::instance();
	IDisassembly::instance();
	ArchitectureFactory::instance();
	InstructionFactory::instance();
	XmlFactory::instance();
	Server::instance();
	Preferences::instance();
	NameMangler::instance();

	std::string confDir = conf.getPath(Configuration::DIR_CONFIGURATION);
	std::string localDir = conf.getPath(Configuration::DIR_LOCAL);
	std::string remoteDir = conf.getPath(Configuration::DIR_REMOTE);

	::mkdir(conf.getBasePath().c_str(), 0744);
	::mkdir(confDir.c_str(), 0744);
	::mkdir(localDir.c_str(), 0744);
	::mkdir(remoteDir.c_str(), 0744);

	// Parse all XML files with configuration and instruction models
	g_instance->parseDirectory(confDir);
	if (conf.readStoredModels()) {
		panic_if (!XmlFactory::instance().parse(built_in_instruction_models_xml),
				"Can't parse built-in instruction models");
	}
	g_instance->parseDirectory(localDir);
	g_instance->parseDirectory(remoteDir);
	g_instance->parseDirectory(confDir);
}

void EmilPro::destroy()
{
	Model::instance().destroy();
	SymbolFactory::instance().destroy();
	IDisassembly::instance().destroy();
	InstructionFactory::instance().destroy();
	ArchitectureFactory::instance().destroy();
	//Server::instance().destroy();
	Preferences::instance().destroy();
	XmlFactory::instance().destroy();
	Configuration::instance().destroy();
	NameMangler::instance().destroy();

	if (g_instance)
		delete g_instance;

	g_instance = NULL;
}

std::string EmilPro::parseDirectory(std::string& dirName)
{
		struct dirent *de;
		DIR *dir;
		std::string out;

		dir = ::opendir(dirName.c_str());
		if (!dir)
			return out;

		for (de = readdir(dir);
				de;
				de = readdir(dir)) {
			struct stat st;

			std::string name(de->d_name);
			std::string curPath = dirName + "/" + name;

			if (name == "." || name == "..")
				continue;

			// Add this file
			if (name.find(".xml") != std::string::npos) {
				out += parseFile(curPath);
				continue;
			}

			lstat(std::string(dirName + "/" + name).c_str(), &st);
			// Recuse and check the next directory level
			if (S_ISDIR(st.st_mode))
				out += parseDirectory(curPath);
		}

		::closedir(dir);

		return out;
}

std::string EmilPro::parseFile(std::string& fileName)
{
	size_t sz;
	char *p;

	p = (char *)read_file(&sz, "%s", fileName.c_str());
	if (!p)
		return std::string();

	std::string out(p);
	free(p);

	XmlFactory::instance().parse(out);

	return out;
}

