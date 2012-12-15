#pragma once

#include <stdint.h>
#include <list>

namespace emilpro
{
	class IInstruction;

	class ISymbol
	{
	public:
		enum SymbolType
		{
			SYM_NORMAL,
			SYM_DYNAMIC,
		};

		typedef std::list<IInstruction *> InstructionList_t;

		virtual enum SymbolType getType() = 0;

		virtual const char *getName() = 0;

		virtual void *getEntry() = 0;

		virtual size_t getSize() = 0;

		virtual InstructionList_t &getInstructions() = 0;
	};
}
