#pragma once

#include "iprovider.hh"
#include <iinstruction.hh>

namespace emilpro
{
	class IDisassemblyProvider : public IProvider
	{
	public:
		virtual ~IDisassemblyProvider()
		{
		}

		virtual InstructionList_t execute(void *data, size_t size, uint64_t address) = 0;

		/**
		 * Whether the disassembler use PC-relative offsets or mangled
		 * absolute ones.
		 *
		 * @return true if the offsets are relative, false if absolute
		 */
		virtual bool relativeAddressOffsets() = 0;
	};

}
