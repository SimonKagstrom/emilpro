#include <utils.hh>
#include <emilpro.hh>
#include <instructionfactory.hh>

#include <string>
#include <map>
#include <stdio.h>

using namespace emilpro;

int main(int argc, const char *argv[])
{
	if (argc != 2) {
		printf("Too few arguments:\n"
				"Usage: XXX out-dir\n"
				);
		exit(1);
	}

	const char *dir = argv[1];

	// Reads all models
	EmilPro::init();

	std::map<std::string, std::string> archToXml;
	InstructionFactory::InstructionModelList_t lst = InstructionFactory::instance().getInstructionModels();

	for (InstructionFactory::InstructionModelList_t::iterator it = lst.begin();
			it != lst.end();
			++it) {
		InstructionFactory::IInstructionModel *cur = *it;
		std::string arch = ArchitectureFactory::instance().getNameFromArchitecture(cur->getArchitecture());

		archToXml[arch] += cur->toXml();
	}

	for (std::map<std::string, std::string>::iterator it = archToXml.begin();
			it != archToXml.end();
			++it) {
		std::string arch = it->first;
		std::string cur = it->second;

		write_file((void *)cur.c_str(), cur.size(),
				"%s/%s.xml",
				dir,
				arch.c_str()
				);
	}
}

