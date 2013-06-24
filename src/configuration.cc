#include <configuration.hh>
#include <utils.hh>

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
		m_readStoredModels(true)
{
	if (m_basePath == "")
		m_basePath = get_home_directory() + "/.emilpro";
}



