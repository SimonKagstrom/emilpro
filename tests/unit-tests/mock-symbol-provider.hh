#pragma once

#include <utils.hh>

#include "test.hh"

#include "symbol-fixture.hh"

class MockSymbolProvider : public ISymbolProvider
{
public:
	MockSymbolProvider() :
		m_listener(NULL)
	{
		SymbolFactory::instance().registerProvider(this);
	}

	unsigned match(void *data, size_t dataSize)
	{
		return ISymbolProvider::PERFECT_MATCH;
	}

	bool parse(void *data, size_t dataSize, ISymbolListener *listener)
	{
		m_listener = listener;

		return true;
	}

	void addSymbol(uint64_t start, uint64_t end,
			enum ISymbol::SymbolType symbolType = ISymbol::SYM_TEXT)
	{
		ASSERT_TRUE(m_listener);

		ISymbol &p = SymbolFactory::instance().createSymbol(ISymbol::LINK_NORMAL,
				symbolType,
				fmt("%llx..%llx\n", (long long)start, (long long)end).c_str(),
				NULL,
				start,
				end - start,
				start,
				true,
				true,
				true,
				1);

		m_listener->onSymbol(p);
	}

private:
	ISymbolListener *m_listener;
};
