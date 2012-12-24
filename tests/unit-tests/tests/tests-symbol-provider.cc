#include "../test.hh"

#include <symbolfactory.hh>
#include <isymbolprovider.hh>

using namespace emilpro;

TESTSUITE(symbol_provider)
{
	TEST(nonPerfectMatches)
	{
		SymbolFactory &factory = SymbolFactory::instance();
		unsigned res;

		res = factory.parseBestProvider(NULL, 0);
		ASSERT_TRUE(res != ISymbolProvider::PERFECT_MATCH);

		char notElf[] = "\177ElF-ngt-annat";
		res = factory.parseBestProvider(&notElf, sizeof(notElf));
		ASSERT_TRUE(res != ISymbolProvider::PERFECT_MATCH);

		char unparseableElf[] = "\177ELFjunk";
		res = factory.parseBestProvider(&unparseableElf, sizeof(unparseableElf));
		ASSERT_TRUE(res != ISymbolProvider::PERFECT_MATCH);
	};
}
