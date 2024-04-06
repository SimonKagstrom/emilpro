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
			uint64_t fileOffset,
			const char *name,
			bool isAllocated,
			bool isWriteable,
			bool isExecutable,
			unsigned int nr) :
				m_type(type),
				m_linkage(linkage),
				m_data(data),
				m_address(address),
				m_size(size),
				m_fileOffset(fileOffset),
				m_name(name),
				m_isAllocated(isAllocated),
				m_isWriteable(isWriteable),
				m_isExecutable(isExecutable),
				m_nr(nr)
	{
	}

	enum ISymbol::LinkageType getLinkage() const
	{
		return m_linkage;
	}

	enum ISymbol::SymbolType getType() const
	{
		return m_type;
	}

	bool isAllocated() const
	{
		return m_isAllocated;
	}

	bool isWriteable() const
	{
		return m_isWriteable;
	}

	bool isExecutable() const
	{
		return m_isExecutable;
	}

	std::string getName() const
	{
		return m_name.c_str();
	}

	void *getDataPtr() const
	{
		return m_data;
	}

	uint64_t getAddress() const
	{
		return m_address;
	}

	uint64_t getSize() const
	{
		return m_size;
	}

	uint64_t getFileOffset() const
	{
		return m_fileOffset;
	}

	void setSize(uint64_t size)
	{
		m_size = size;
	}

	unsigned int getNr() const
	{
		return m_nr;
	}

private:
	enum ISymbol::SymbolType m_type;
	enum ISymbol::LinkageType m_linkage;
	void *m_data;
	uint64_t m_address;
	uint64_t m_size;
	uint64_t m_fileOffset;
	std::string m_name;
	bool m_isAllocated;
	bool m_isWriteable;
	bool m_isExecutable;
	unsigned int m_nr;
};

class Relocation : public IRelocation
{
public:
	Relocation(const ISymbol &symbol, uint64_t sourceAddress,
			size_t size, int64_t offset) :
		m_symbol(symbol),
		m_sourceAddress(sourceAddress),
		m_size(size),
		m_offset(offset)
	{
	}

	uint64_t getSourceAddress() const
	{
		return m_sourceAddress;
	}

	size_t getSize() const
	{
		return m_size;
	}

	const ISymbol &getTargetSymbol() const
	{
		return m_symbol;
	}

	int64_t getTargetOffset() const
	{
		return m_offset;
	}

private:
	const ISymbol &m_symbol;
	uint64_t m_sourceAddress;
	size_t m_size;
	int64_t m_offset;
};


void SymbolFactory::registerListener(ISymbolListener *listener, IRelocationListener *relocListener)
{
	m_listeners.push_back(listener);
	m_relocationListeners.push_back(relocListener);
}

void SymbolFactory::registerProvider(ISymbolProvider *provider)
{
	m_providers.push_back(provider);
}

void SymbolFactory::registerLineProvider(ILineProvider *provider)
{
	m_lineProviders.push_back(provider);
}

ILineProvider *SymbolFactory::getLineProvider()
{
	if (m_lineProviders.empty())
		return NULL;

	return m_lineProviders.front();
}


ISymbol &SymbolFactory::createSymbol(enum ISymbol::LinkageType linkage,
		enum ISymbol::SymbolType type,
		const char *name,
		void *data,
		uint64_t address,
		uint64_t size,
		uint64_t fileOffset,
		bool isAllocated,
		bool isWriteable,
		bool isExecutable,
		unsigned int nr)
{
	Symbol *cur = new Symbol(type, linkage, data, address, size, fileOffset,
			name, isAllocated, isWriteable, isExecutable, nr);

	m_symbols.push_back(cur);

	return *cur;
}

IRelocation &SymbolFactory::createRelocation(const ISymbol &symbol, uint64_t sourceAddress, size_t size, int64_t offset)
{
	// FIXME!
	return *new Relocation(symbol, sourceAddress, size, offset);
}


unsigned SymbolFactory::parseBestProvider(void *data, size_t size)
{
	unsigned highest = IProvider::NO_MATCH;
	ISymbolProvider *best = NULL;

	for (SymbolProviders_t::iterator it = m_providers.begin();
			it != m_providers.end();
			++it) {
		ISymbolProvider *p = *it;
		unsigned cur = p->match(data, size);

		if (cur > highest) {
			highest = cur;
			best = p;
		}
	}

	if (!best)
		return highest;

	bool res = best->parse(data, size, &m_metaListener, &m_metaListener);

	if (!res)
		return IProvider::NO_MATCH;

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

void SymbolFactory::MetaListener::onRelocation(IRelocation &reloc)
{
	for (auto it : m_parent.m_relocationListeners) {
		IRelocationListener *cur = it;

		cur->onRelocation(reloc);
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

		createBfdProvider();
	}

	return *g_instance;
}
