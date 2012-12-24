#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <list>

namespace emilpro
{
	class ISymbol
	{
	public:
		enum LinkageType
		{
			LINK_NORMAL,
			LINK_DYNAMIC,
		};

		enum SymbolType
		{
			SYM_TEXT,
			SYM_DATA,
			SYM_FILE,
			SYM_SECTION,
		};


		virtual ~ISymbol()
		{
		}

		virtual enum LinkageType getLinkage() = 0;

		virtual enum SymbolType getType() = 0;

		virtual const char *getName() = 0;

		virtual void *getDataPtr() = 0;

		virtual uint64_t getAddress() = 0;

		virtual uint64_t getSize() = 0;
	};
}
