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
		static IDisassembly &instance();

		virtual InstructionList_t execute(void *data, size_t size, uint64_t address) = 0;

		virtual void destroy() = 0;

	protected:
		virtual ~IDisassembly()
		{
		}
	};
}
