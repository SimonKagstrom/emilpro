#pragma once

#include <string>

namespace emilpro
{
	class Configuration
	{
	public:
		typedef enum
		{
			DIR_LOCAL,
			DIR_REMOTE,
			DIR_CONFIGURATION,
			DIR_SERVER_STATISTICS,
		} Dir_t;

		std::string getBasePath();

		std::string getPath(Dir_t dir);

		std::string getServerUrl();

		bool readStoredModels();


		// Setters
		void setReadStoredModels(bool readStoredModels);


		void destroy();

		static Configuration &instance();

		static void setBaseDirectory(const std::string base);

	private:
		Configuration();

		std::string m_basePath;
		bool m_readStoredModels;
	};
}
