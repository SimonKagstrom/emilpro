#pragma once

#include <symbolfactory.hh>
#include <isymbolprovider.hh>

#include <unordered_map>

using namespace emilpro;

class SymbolFixture : public ISymbolListener
{
public:
	SymbolFixture()
	{
		SymbolFactory &factory = SymbolFactory::instance();

		factory.registerListener(this);
	}

	virtual ~SymbolFixture()
	{
		SymbolFactory &factory = SymbolFactory::instance();

		factory.destroy();
	}

	void onSymbol(ISymbol &sym)
	{
		m_symbolNames[sym.getName()] = &sym;
		m_symbolAddrs[sym.getAddress()] = &sym;
	}

	std::unordered_map<std::string, ISymbol *> m_symbolNames;
	std::unordered_map<uint64_t, ISymbol *> m_symbolAddrs;
};
