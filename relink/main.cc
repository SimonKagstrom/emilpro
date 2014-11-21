#include <model.hh>
#include <emilpro.hh>
#include <utils.hh>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>

#include <elf.h>

#include <functional>

using namespace emilpro;

static void walkDir(const std::string& dirName, std::function<void(const std::string &)> onFile)
{
	struct dirent *de;
	DIR *dir;

	dir = ::opendir(dirName.c_str());
	if (!dir)
		return;

	for (de = readdir(dir);
			de;
			de = readdir(dir)) {
		struct stat st;

		std::string name(de->d_name);
		std::string curPath = dirName + "/" + name;

		if (name == "." || name == "..")
			continue;


		lstat(std::string(dirName + "/" + name).c_str(), &st);
		// Recuse and check the next directory level
		if (S_ISREG(st.st_mode)) {
			onFile(curPath);
			continue;
		} else if (S_ISDIR(st.st_mode))
			walkDir(curPath, onFile);
	}

	::closedir(dir);

	return;
}

static void *checkElf(const std::string &path, unsigned int e_type, size_t &outSz)
{
	size_t sz;
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)peek_file(&sz, "%s", path.c_str());

	if (!ehdr)
		return nullptr;

	if (sz < sizeof(Elf32_Ehdr))
		return nullptr;

	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0)
		return nullptr;

	if (ehdr->e_type != e_type)
		return nullptr;

	return read_file(&outSz, "%s", path.c_str());
}

std::unordered_map<std::string, unsigned int> binarySymbols;
std::unordered_map<std::string, unsigned int> keepSymbols;

static void parseFile(const std::string &path)
{
	size_t sz;
	void *p = checkElf(path, ET_EXEC, sz);

	if (!p)
		return;

	// HACK!
	if (sz > 10 * 1024 * 1024) {
		return;
		free(p);
	}

	printf("XXX: %s\n", path.c_str());
	Model::instance().destroy();
	auto &model = Model::instance();

	model.addData(p, sz);
	model.parseAll();
	while (!model.parsingComplete())
		;

	auto syms = model.getSymbols();
	for (auto &it : syms) {
		const ISymbol *cur = it;

		if (cur->getLinkage() == ISymbol::LINK_UNDEFINED)
			binarySymbols[cur->getName()]++;
	}
	free(p);
}

static void parseSolibs(const std::string &path)
{
	size_t sz;
	void *p = checkElf(path, ET_DYN, sz);

	if (!p)
		return;

	printf("YYY: %s\n", path.c_str());
	Model::instance().destroy();
	auto &model = Model::instance();

	model.addData(p, sz);
	model.parseAll();
	while (!model.parsingComplete())
		;

	auto syms = model.getSymbols();
	for (auto &it : syms) {
		const ISymbol *cur = it;

		if (cur->getLinkage() == ISymbol::LINK_DYNAMIC &&
				binarySymbols.find(cur->getName()) != binarySymbols.end())
			keepSymbols[cur->getName()]++;
	}
	free(p);
}

int main(int argc, const char *argv[])
{
	if (argc < 2)
		return 0;

	EmilPro::init();

	walkDir(argv[1], parseFile);
	walkDir(argv[1], parseSolibs);
	for (auto &it : keepSymbols) {
		printf("Will keep %s: %d\n", it.first.c_str(), it.second);
	}

	return 0;
}
