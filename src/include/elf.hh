#pragma once

#include <sys/types.h>
#include <list>

namespace emilpro
{
	class IFunction;

	class IElf
	{
	public:
		typedef std::list<IFunction *> FunctionList_t;

		class IFunctionListener
		{
		public:
			virtual void onFunction(IFunction &fn) = 0;
		};

		static IElf *open(const char *filename);


		virtual bool parse(IFunctionListener *listener) = 0;

		virtual FunctionList_t functionByName(const char *name) = 0;

		virtual IFunction *functionByAddress(void *addr) = 0;
	};
}
