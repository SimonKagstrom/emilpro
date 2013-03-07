#pragma once

namespace emilpro
{
	class Configuration
	{
	public:
		typedef enum
		{
			DIR_LOCAL,
			DIR_INSTALLED,
			DIR_REMOTE,
			DIR_CONFIGURATION,
		} Dir_t;

		virtual std::string &getBasePath() = 0;

		virtual std::string &getPath(Dir_t dir) = 0;

		static Configuration &instance();
	};
}
