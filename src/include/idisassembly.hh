#pragma once

#include <sys/types.h>
#include <stdint.h>
#include <list>

namespace emilpro
{
	class IInstruction;

	class IDisassembly
	{
	public:
		typedef std::list<IInstruction *> InstructionList_t;

		virtual ~IDisassembly()
		{
		}

		static IDisassembly &getInstance();

		virtual InstructionList_t execute(void *data, size_t size) = 0;
	};
}
