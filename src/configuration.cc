#include <configuration.hh>
#include <utils.hh>

using namespace emilpro;

std::string Configuration::getBasePath()
{
	if (m_basePath == "")
		m_basePath = get_home_directory() + "/.emilpro";

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

Configuration& Configuration::instance()
{
	if (!g_instance) {
		g_instance = new Configuration();
	}

	return *g_instance;
}

