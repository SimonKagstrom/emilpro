#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <list>
#include <string>

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

		virtual bool isAllocated() const = 0;

		virtual bool isWriteable() const = 0;

		virtual std::string getName() const = 0;

		virtual std::string getMangledName() const = 0;

		virtual void *getDataPtr() const = 0;

		virtual uint64_t getAddress() const = 0;

		virtual uint64_t getSize() const = 0;


		virtual void setSize(uint64_t size) = 0;
	};
}
