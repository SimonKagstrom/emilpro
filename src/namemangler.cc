#include <namemangler.hh>

#include <bfd.h>
#include <demangle.h>

using namespace emilpro;

std::string NameMangler::mangle(const std::string& name)
{
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

NameMangler::NameMangler()
{
}
