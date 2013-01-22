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

		virtual enum LinkageType getLinkage() const = 0;

		virtual enum SymbolType getType() const = 0;

		virtual const char *getName() const = 0;

		virtual void *getDataPtr() const = 0;

		virtual uint64_t getAddress() const = 0;

		virtual uint64_t getSize() const = 0;


		virtual void setSize(uint64_t size) = 0;
	};
}
