#pragma once

#include <sys/types.h>
#include <list>

namespace emilpro
{
	class ISymbol;

	class IElf
	{
	public:
		typedef std::list<ISymbol *> FunctionList_t;

		class ISymbolListener
		{
		public:
			virtual void onFunction(ISymbol &fn) = 0;
		};

		static IElf *open(const char *filename);


		virtual bool parse(ISymbolListener *listener) = 0;
	};
}
