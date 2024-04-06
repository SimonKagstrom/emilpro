#pragma once

#include <stddef.h>
#include <stdint.h>

namespace emilpro
{
	class IObject
	{
	public:
		virtual uint8_t *getRawData(size_t &sz) = 0;
	};
}
