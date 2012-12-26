#pragma once

#include <string>

namespace emilpro
{
	class IInstruction
	{
	public:
		virtual ~IInstruction()
		{
		}

		virtual uint64_t getAddress() = 0;
	};
}
