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

		std::string getFileName();

		bool readStoredModels();

		bool parse(unsigned int argc, const char *argv[]);

		// Setters
		void setReadStoredModels(bool readStoredModels);


		void destroy();

		static Configuration &instance();

		static void setBaseDirectory(const std::string base);

	private:
		Configuration();

		bool usage();

		std::string m_basePath;
		bool m_readStoredModels;
		std::string m_fileName;
	};
}
