#include <emilpro.hh>
#include <model.hh>
#include <architecturefactory.hh>
#include <symbolfactory.hh>
#include <instructionfactory.hh>
#include <idisassembly.hh>
#include <xmlfactory.hh>
#include <configuration.hh>
#include <utils.hh>

#include <sys/stat.h>
#include <sys/types.h>

using namespace emilpro;

void EmilPro::init()
{
	Configuration &conf = Configuration::instance();

	::mkdir(conf.getBasePath().c_str(), 0744);
	::mkdir(conf.getPath(Configuration::DIR_CONFIGURATION).c_str(), 0744);
	::mkdir(conf.getPath(Configuration::DIR_LOCAL).c_str(), 0744);
	::mkdir(conf.getPath(Configuration::DIR_REMOTE).c_str(), 0744);
}

void EmilPro::destroy()
{
	Model::instance().destroy();
	SymbolFactory::instance().destroy();
	IDisassembly::instance().destroy();
	ArchitectureFactory::instance().destroy();
	InstructionFactory::instance().destroy();
	XmlFactory::instance().destroy();
}
