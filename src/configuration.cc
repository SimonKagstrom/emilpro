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
	case DIR_INSTALLED:
		out = "../../../emilpro/"; // FIXME!
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
	return "http://www.emilpro.com/emilpro-submit.cgi";
}

Configuration& Configuration::instance()
{
	panic_if (!g_instance,
			"Use-before-create");

	return *g_instance;
}

void Configuration::create()
{
	g_instance = new Configuration();
}

static std::string g_base = "";
void Configuration::setBaseDirectory(const std::string base)
{
	g_base = base;
}


Configuration::Configuration() :
		m_basePath(g_base)
{
	if (m_basePath == "")
		m_basePath = get_home_directory() + "/.emilpro";
}



