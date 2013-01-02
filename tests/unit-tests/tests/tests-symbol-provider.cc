#include "../test.hh"

#include <symbolfactory.hh>
#include <isymbolprovider.hh>
#include <idisassembly.hh>

#include <utils.hh>

#include <unordered_map>

using namespace emilpro;

class FactoryFixture : public ISymbolListener
{
public:
	FactoryFixture()
	{
		SymbolFactory &factory = SymbolFactory::instance();

		factory.registerListener(this);
	}

	~FactoryFixture()
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

TESTSUITE(symbol_provider)
{
	TEST(nonPerfectMatches, FactoryFixture)
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

	TEST(validElf, FactoryFixture)
	{
		SymbolFactory &factory = SymbolFactory::instance();
		unsigned res;

		size_t sz;
		void *data = read_file(&sz, "%s/test-binary", crpcut::get_start_dir());
		ASSERT_TRUE(data != (void *)NULL);

		res = factory.parseBestProvider(data, sz);
		ASSERT_TRUE(res > ISymbolProvider::NO_MATCH);

		ASSERT_TRUE(m_symbolNames.find("main") != m_symbolNames.end());
		ASSERT_TRUE(m_symbolNames.find("global_data") != m_symbolNames.end());

		ISymbol *sym = m_symbolNames["main"];
		ASSERT_TRUE(sym != (void *)NULL);

		ASSERT_TRUE(sym->getType() == ISymbol::SYM_TEXT);
		ASSERT_TRUE(sym->getSize() > 1U);
		ASSERT_TRUE(sym->getDataPtr() != (void *)NULL);
		IDisassembly &dis = IDisassembly::instance();

		// Disassemble main()
		InstructionList_t insns = dis.execute(sym->getDataPtr(), sym->getSize(), sym->getAddress());
		ASSERT_TRUE(insns.size() > 0U);


		sym = m_symbolNames["global_data"];
		ASSERT_TRUE(sym != (void *)NULL);
		ASSERT_TRUE(sym->getSize() > 1U);
		ASSERT_TRUE(sym->getType() == ISymbol::SYM_DATA);
	}

	TEST(deduceSymbolSize, FactoryFixture)
	{
		SymbolFactory &factory = SymbolFactory::instance();
		unsigned res;

		size_t sz;
		void *data = read_file(&sz, "%s/test-binary", crpcut::get_start_dir());
		ASSERT_TRUE(data != (void *)NULL);

		res = factory.parseBestProvider(data, sz);
		ASSERT_TRUE(res > ISymbolProvider::NO_MATCH);

		ISymbol *sym;

		sym = m_symbolNames["asm_sym1"];
		ASSERT_TRUE(sym != (void *)NULL);
		ASSERT_TRUE(sym->getSize() == 128U);
		ASSERT_TRUE(sym->getType() == ISymbol::SYM_DATA);

		sym = m_symbolNames["asm_sym2"];
		ASSERT_TRUE(sym != (void *)NULL);
		ASSERT_TRUE(sym->getSize() == 4U);
		ASSERT_TRUE(sym->getType() == ISymbol::SYM_DATA);
	}

	TEST(deduceLastSymbolSize, FactoryFixture)
	{
		SymbolFactory &factory = SymbolFactory::instance();
		unsigned res;

		size_t sz;
		void *data = read_file(&sz, "%s/test-binary-asm-only", crpcut::get_start_dir());
		ASSERT_TRUE(data != (void *)NULL);

		res = factory.parseBestProvider(data, sz);
		ASSERT_TRUE(res > ISymbolProvider::NO_MATCH);

		ISymbol *sym;

		sym = m_symbolNames["_start"];
		ASSERT_TRUE(sym != (void *)NULL);
		ASSERT_TRUE(sym->getSize() == 128U);
		ASSERT_TRUE(sym->getType() == ISymbol::SYM_TEXT);
	}
}
