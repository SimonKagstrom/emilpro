#pragma once

#include <stdlib.h> // size_t

namespace emilpro
{
	class ISymbolListener;
	class IRelocationListener;

	class ISymbolProvider
	{
	public:
		enum MatchLimits
		{
			NO_MATCH = 0,
			PERFECT_MATCH = 0xffffffff,
		};

		virtual ~ISymbolProvider()
		{
		}

		virtual unsigned match(void *data, size_t dataSize) = 0;

		virtual bool parse(void *data, size_t dataSize, ISymbolListener *, IRelocationListener *) = 0;
	};
};
