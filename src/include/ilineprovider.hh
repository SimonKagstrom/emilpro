#pragma once

#include <string>

namespace emilpro
{
	class ILineProvider
	{
	public:
		class FileLine
		{
		public:
			FileLine() :
				m_isValid(false)
			{
			}

			std::string m_file;
			unsigned int m_lineNr;
			bool m_isValid;
		};

		virtual ~ILineProvider()
		{
		}

		virtual FileLine getLineByAddress(uint64_t addr) = 0;
	};
}
