#include <ui-helpers.hh>

#include <utils.hh>

using namespace emilpro;

std::string UiHelpers::getFileContents(const std::string& fileName)
{
	size_t sz;
	char *p = (char *)read_file(&sz, "%s", fileName.c_str());
	if (!p)
		return "";

	std::string data(p, sz);
	free(p);

	return data;
}

const ISymbol* UiHelpers::getBestSymbol(uint64_t address, const std::string &currentName,
		unsigned long filterMask)
{
	Model &model = Model::instance();

	const Model::SymbolList_t nearestSyms = model.getNearestSymbol(address);

	if (nearestSyms.empty())
		return NULL;

	uint64_t symbolAddress = IInstruction::INVALID_ADDRESS;
	uint64_t sectionAddress = IInstruction::INVALID_ADDRESS;

	for (Model::SymbolList_t::const_iterator sIt = nearestSyms.begin();
			sIt != nearestSyms.end();
			++sIt) {
		ISymbol *sym = *sIt;

		if (sym->getType() == ISymbol::SYM_SECTION) {
			sectionAddress = sym->getAddress();
			continue;
		}

		if (sym->getType() != ISymbol::SYM_TEXT && sym->getType() != ISymbol::SYM_DATA)
			continue;

		// Found a "meaningful" symbol
		symbolAddress = sym->getAddress();
		break;
	}

	// No text/data symbol found, just use the section
	if (symbolAddress == IInstruction::INVALID_ADDRESS)
		symbolAddress = sectionAddress;


	Model::SymbolList_t syms = model.getSymbolExact(symbolAddress);
	if (syms.empty()) {
		warning("Can't get symbol\n");
		return NULL;
	}

	const ISymbol *largest = syms.front();

	for (Model::SymbolList_t::iterator it = syms.begin();
			it != syms.end();
			++it) {
		const ISymbol *cur = *it;
		enum ISymbol::SymbolType type = cur->getType();

		if (type != ISymbol::SYM_TEXT && type != ISymbol::SYM_DATA)
			continue;

		if ((largest->getType() & filterMask) == 0)
			largest = cur;

		if (cur->getSize() > largest->getSize())
			largest = cur;

		// Prioritize the selected name
		if (cur->getName() == currentName) {

			largest = cur;
			break;
		}
	}

	return largest;
}
