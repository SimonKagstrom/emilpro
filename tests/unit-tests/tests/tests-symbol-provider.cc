#include "../test.hh"

#include <symbolfactory.hh>
#include <isymbolprovider.hh>

#include <utils.hh>

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

	TEST(validElf)
	{
		SymbolFactory &factory = SymbolFactory::instance();
		unsigned res;

		size_t sz;
		void *data = read_file(&sz, "%s/test-binary", crpcut::get_start_dir());
		ASSERT_TRUE(data != (void *)NULL);

		res = factory.parseBestProvider(data, sz);
		ASSERT_TRUE(res > ISymbolProvider::NO_MATCH);
	}
}
