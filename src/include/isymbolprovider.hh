#pragma once

namespace emilpro
{
	class ISymbolListener;

	class ISymbolProvider
	{
	public:
		virtual ~ISymbolProvider()
		{
		}

		virtual unsigned match(void *data, void *dataSize) = 0;

		virtual bool parse(ISymbolListener *) = 0;
	};
};
