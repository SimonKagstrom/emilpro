#pragma once

#include <string>

namespace emilpro
{
	class EmilPro
	{
	public:
		static void init();

		static void destroy();

	private:
		std::string parseDirectory(std::string &dir);

		std::string parseFile(std::string &fileName);
	};
}
