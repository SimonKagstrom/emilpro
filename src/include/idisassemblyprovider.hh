#pragma once

#include "iprovider.hh"

namespace emilpro
{
	class IDisassemblyProvider : public IProvider
	{
	public:
		virtual ~IDisassemblyProvider()
		{
		}

		virtual InstructionList_t execute(void *data, size_t size, uint64_t address) = 0;
	};

}
