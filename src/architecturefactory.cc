#include <stdlib.h>
#include <architecturefactory.hh>

using namespace emilpro;


ArchitectureFactory::ArchitectureFactory() :
		m_architecture(ARCH_UNKNOWN)
{
}

ArchitectureFactory::~ArchitectureFactory()
{
}


void ArchitectureFactory::registerListener(IArchitectureListener *listener)
{
	listener->onArchitectureDetected(m_architecture);

	m_listeners.push_back(listener);
}

void ArchitectureFactory::provideArchitecture(Architecture_t arch)
{
	if (arch == m_architecture)
		return;

	m_architecture = arch;

	for (ArchitectureListeners_t::iterator it = m_listeners.begin();
			it != m_listeners.end();
			++it) {
		IArchitectureListener *cur = *it;

		cur->onArchitectureDetected(m_architecture);
	}
}



static ArchitectureFactory *g_instance;
void ArchitectureFactory::destroy()
{
	g_instance = NULL;
	delete this;
}

ArchitectureFactory & ArchitectureFactory::instance()
{

	if (!g_instance)
		g_instance = new ArchitectureFactory();

	return *g_instance;
}
