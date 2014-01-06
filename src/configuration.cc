#include <configuration.hh>
#include <utils.hh>

#include <getopt.h>

using namespace emilpro;

std::string Configuration::getBasePath()
{
	return m_basePath;
}

std::string Configuration::getPath(Dir_t dir)
{
	std::string out;

	switch (dir)
	{
	case DIR_LOCAL:
		out = getBasePath() + "/local";
		break;
	case DIR_REMOTE:
		out = getBasePath() + "/remote";
		break;
	case DIR_CONFIGURATION:
		out = getBasePath() + "/configuration";
		break;
	case DIR_SERVER_STATISTICS:
		out = m_serverStatisticsDir;
		break;
	default:
		break;
	}

	return out;
}

static Configuration *g_instance;

void Configuration::destroy()
{
	g_instance = NULL;

	delete this;
}

std::string emilpro::Configuration::getServerUrl()
{
	return "http://www.emilpro.com/cgi-bin/emilpro-upload.cgi";
}

Configuration& Configuration::instance()
{
	if (!g_instance)
		g_instance = new Configuration();

	return *g_instance;
}

static std::string g_base = "";
void Configuration::setBaseDirectory(const std::string base)
{
	g_base = base;
}

void Configuration::setServerStatisticsDirectory(const std::string dir)
{
	m_serverStatisticsDir = dir;
}


bool Configuration::readStoredModels()
{
	return m_readStoredModels;
}

void Configuration::setReadStoredModels(bool readStoredModels)
{
	m_readStoredModels = readStoredModels;
}

Configuration::Configuration() :
		m_basePath(g_base),
		m_readStoredModels(true),
		m_debugLevel(Configuration::DBG_SILENT),
		m_serverStatisticsDir("/www/emilpro")
{
	if (m_basePath == "")
		m_basePath = get_home_directory() + "/.emilpro";
}

bool Configuration::parse(unsigned int argc, const char* argv[])
{
	static const struct option long_options[] = {
			{"help", no_argument, 0, 'h'},
			{"debug", required_argument, 0, 'D'},
			{0,0,0,0}
	};

	optind = 0;
	optarg = 0;
	while (1) {
		int option_index = 0;
		int c;

		c = getopt_long (argc, (char **)argv,
				"hD", long_options, &option_index);

		/* No more options */
		if (c == -1)
			break;

		switch (c) {
		case 0:
			break;
		case 'h':
			return usage();
		case 'D':
			if (!string_is_integer(std::string(optarg)))
				return usage();
			m_debugLevel = (Configuration::DebugLevel_t)string_to_integer(std::string(optarg));
			break;
		default:
			break;
		}
	}

	if (optind < (int)argc)
		m_fileName = argv[optind];

	return true;
}

std::string Configuration::getFileName()
{
	return m_fileName;
}

Configuration::DebugLevel_t Configuration::getDebugLevel()
{
	return m_debugLevel;
}

bool Configuration::usage()
{
	printf("Usage: emilpro [OPTIONS] [infile]\n"
			"\n"
			"Where [OPTIONS] are\n"
			" -h, --help              this text\n"
			" --debug=n               increase debugging level (default: 0)\n"
	);

	return false;
}
