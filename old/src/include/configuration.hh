#pragma once

#include <string>

namespace emilpro
{
	class Configuration
	{
	public:
		typedef enum
		{
			DBG_SILENT   = 0,
			DBG_ERRORS   = 1,
			DBG_NETWORK  = 2,
		} DebugLevel_t;

		typedef enum
		{
			DIR_LOCAL,
			DIR_REMOTE,
			DIR_CONFIGURATION,
			DIR_SERVER_STATISTICS,
		} Dir_t;

		typedef enum
		{
			CAP_NONE = 0,
			CAP_HTML_DESCRIPTIONS = 1,
		} Capabilities_t;

		std::string getBasePath();

		std::string getPath(Dir_t dir);

		std::string getServerUrl();

		std::string getFileName();

		DebugLevel_t getDebugLevel();

		Capabilities_t getCapabilties() const;

		void setDebugLevel(DebugLevel_t lvl);

		void setCapabilties(Capabilities_t cap);

		bool readStoredModels();

		bool parse(unsigned int argc, const char *argv[]);

		// Setters
		void setReadStoredModels(bool readStoredModels);

		void setServerStatisticsDirectory(const std::string dir);


		void destroy();

		static Configuration &instance();

		static void setBaseDirectory(const std::string base);

	private:
		Configuration();

		bool usage();

		std::string m_basePath;
		bool m_readStoredModels;
		std::string m_fileName;
		DebugLevel_t m_debugLevel;
		std::string m_serverStatisticsDir;
		Capabilities_t m_capabilities;
	};
}
