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
			LINK_UNDEFINED
		};

		enum SymbolType
		{
			SYM_NONE    = 0,
			SYM_TEXT    = 1,
			SYM_DATA    = 2,
			SYM_FILE    = 4,
			SYM_SECTION = 8,
		};


		virtual ~ISymbol()
		{
		}

		virtual enum LinkageType getLinkage() const = 0;

		virtual enum SymbolType getType() const = 0;

		virtual uint32_t getRawType() const = 0;

		virtual void setRawType(uint32_t rawType) = 0;

		virtual bool isAllocated() const = 0;

		virtual bool isWriteable() const = 0;

		virtual bool isExecutable() const = 0;

		virtual std::string getName() const = 0;

		virtual void *getDataPtr() const = 0;

		virtual uint64_t getAddress() const = 0;

		virtual uint64_t getSize() const = 0;

		virtual uint64_t getFileOffset() const = 0;

		virtual unsigned int getNr() const = 0;

		virtual void setSize(uint64_t size) = 0;
	};
}
