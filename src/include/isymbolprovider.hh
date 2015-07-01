#pragma once

#include "iprovider.hh"

#include <stdlib.h> // size_t

namespace emilpro
{
	class ISymbolListener;
	class IRelocationListener;

	class ISymbolProvider : public IProvider
	{
	public:
		virtual ~ISymbolProvider()
		{
		}

		virtual bool parse(void *data, size_t dataSize, ISymbolListener *, IRelocationListener *) = 0;
	};
};
