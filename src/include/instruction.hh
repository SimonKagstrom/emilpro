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

		virtual void *getAddress() = 0;

		virtual std::string &disassemble() = 0;
	};
}
