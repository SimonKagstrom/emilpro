#pragma once

#include <model.hh>
#include <symbolfactory.hh>
#include <isymbol.hh>

#include <string>

class UiHelpers
{
public:
	static std::string getFileContents(const std::string &fileName);

	static std::string getInstructionInfoString(const emilpro::IInstruction &insn, bool richText = false);

	static const emilpro::ISymbol *getBestSymbol(uint64_t address, const std::string &currentName,
			unsigned long filterMask = (emilpro::ISymbol::SYM_SECTION | emilpro::ISymbol::SYM_FILE));
};
