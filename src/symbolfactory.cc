#include <symbolfactory.hh>
#include <isymbolprovider.hh>
#include <isymbol.hh>

#include <string>

#include "providers.hh"

using namespace emilpro;

class Symbol : public ISymbol
{
public:
	Symbol(enum ISymbol::SymbolType type,
			enum ISymbol::LinkageType linkage,
			void *data,
			uint64_t address,
			uint64_t size,
			const char *name) :
				m_type(type),
				m_linkage(linkage),
				m_data(data),
				m_address(address),
				m_size(size),
				m_name(name)
	{
	}

	enum ISymbol::LinkageType getLinkage()
	{
		return m_linkage;
	}

	enum ISymbol::SymbolType getType()
	{
		return m_type;
	}

	const char *getName()
	{
		return m_name.c_str();
	}

	void *getDataPtr()
	{
		return m_data;
	}

	uint64_t getAddress()
	{
		return m_address;
	}

	uint64_t getSize()
	{
		return m_size;
	}

	void setSize(uint64_t size)
	{
		m_size = size;
	}

private:
	enum ISymbol::SymbolType m_type;
	enum ISymbol::LinkageType m_linkage;
	void *m_data;
	uint64_t m_address;
	uint64_t m_size;
	std::string m_name;
};


void SymbolFactory::registerListener(ISymbolListener *listener)
{
	m_listeners.push_back(listener);
}

void SymbolFactory::registerProvider(ISymbolProvider *provider)
{
	m_providers.push_back(provider);
}

ISymbol &SymbolFactory::createSymbol(enum ISymbol::LinkageType linkage,
		enum ISymbol::SymbolType type,
		const char *name,
		void *data,
		uint64_t address,
		uint64_t size)
{
	Symbol *cur = new Symbol(type, linkage, data, address, size, name);

	m_symbols.push_back(cur);

	return *cur;
}

unsigned SymbolFactory::parseBestProvider(void *data, size_t size)
{
	unsigned highest = ISymbolProvider::NO_MATCH;
	ISymbolProvider *best = NULL;

	for (SymbolProviders_t::iterator it = m_providers.begin();
			it != m_providers.end();
			++it) {
		ISymbolProvider *p = *it;
		unsigned cur = p->match(data, size);

		if (cur > highest) {
			highest = cur;
			best = p;
			break;
		}
	}

	if (!best)
		return highest;

	bool res = best->parse(data, size, &m_metaListener);

	if (!res)
		return ISymbolProvider::NO_MATCH;

	return highest;
}

SymbolFactory::MetaListener::MetaListener(SymbolFactory &parent) :
		m_parent(parent)
{
}

void SymbolFactory::MetaListener::onSymbol(ISymbol &sym)
{
	for (SymbolListeners_t::iterator it = m_parent.m_listeners.begin();
			it != m_parent.m_listeners.end();
			++it) {
		ISymbolListener *cur = *it;

		cur->onSymbol(sym);
	}
}

SymbolFactory::SymbolFactory() : m_metaListener(*this)
{
}

SymbolFactory::~SymbolFactory()
{
	for (Symbols_t::iterator it = m_symbols.begin();
			it != m_symbols.end();
			++it) {
		ISymbol *cur = *it;

		delete cur;
	}

	for (SymbolProviders_t::iterator it = m_providers.begin();
			it != m_providers.end();
			++it) {
		ISymbolProvider *cur = *it;

		delete cur;
	}
}


static SymbolFactory *g_instance;
void SymbolFactory::destroy()
{
	g_instance = NULL;

	delete this;
}

SymbolFactory &SymbolFactory::instance()
{
	if (!g_instance) {
		g_instance = new SymbolFactory();

		ISymbolProvider *bfd = createBfdProvider();
		g_instance->registerProvider(bfd);
	}

	return *g_instance;
}
