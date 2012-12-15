#pragma once

#include <sys/types.h>
#include <stdint.h>

namespace emilpro
{
	class IDisassembly
	{
	public:
		class IInstructionListener
		{
		public:
			virtual void onInstruction(off_t offset, const char *ascii) = 0;
		};

		virtual ~IDisassembly()
		{
		}


		static IDisassembly &getInstance();


		virtual bool execute(IInstructionListener *listener,
				uint8_t *data, size_t size) = 0;
	};
}
