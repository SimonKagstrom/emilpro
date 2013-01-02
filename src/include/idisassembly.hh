#pragma once

#include <sys/types.h>
#include <stdint.h>
#include <list>

#include "iinstruction.hh"

namespace emilpro
{
	class IDisassembly
	{
	public:
		virtual ~IDisassembly()
		{
		}

		static IDisassembly &instance();

		virtual InstructionList_t execute(void *data, size_t size, uint64_t address) = 0;
	};
}
