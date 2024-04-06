#pragma once

#include <stdlib.h> // size_t

namespace emilpro
{
	class IProvider
	{
	public:
		enum MatchLimits
		{
			NO_MATCH = 0,
			PERFECT_MATCH = 0xffffffff,
		};

		virtual ~IProvider()
		{
		}

		virtual unsigned match(void *data, size_t dataSize) = 0;
	};
};
