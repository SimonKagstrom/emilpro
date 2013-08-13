#pragma once

#include <string>

namespace emilpro
{
	class NameMangler
	{
	public:
		std::string mangle(const std::string &name);

		void destroy();

		static NameMangler &instance();

	private:
		NameMangler();
	};
}
