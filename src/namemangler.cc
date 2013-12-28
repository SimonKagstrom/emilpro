#include <namemangler.hh>

#include <bfd.h>
#include <demangle.h>

using namespace emilpro;

std::string NameMangler::mangle(const std::string& name)
{
	if (!m_manglingEnabled)
		return name;

	// Use what c++filt uses...
	int demangle_flags = DMGL_PARAMS | DMGL_ANSI | DMGL_VERBOSE;

	char *demangled = cplus_demangle(name.c_str(), demangle_flags);

	std::string out;

	if (demangled)
		out = demangled;
	else
		out = name;

	free(demangled);

	return out;
}

void NameMangler::onPreferencesChanged(const std::string& key,
	const std::string& oldValue, const std::string& newValue)
{
	if (key != "MangleNames")
		return;

	if (newValue == "yes")
		m_manglingEnabled = true;
	else
		m_manglingEnabled = false;

	if (m_listener)
		m_listener->onManglingChanged(m_manglingEnabled);
}

void emilpro::NameMangler::registerListener(IListener *listener)
{
	m_listener = listener;
}

static NameMangler *g_instance;
void NameMangler::destroy()
{
	g_instance = NULL;

	delete this;
}

NameMangler& NameMangler::instance()
{
	if (!g_instance)
		g_instance = new NameMangler();

	return *g_instance;
}

emilpro::NameMangler::~NameMangler()
{
	Preferences::instance().unregisterListener(this);
}

NameMangler::NameMangler() :
	m_manglingEnabled(true),
	m_listener(NULL)
{
	Preferences::instance().registerListener("MangleNames", this);
}
