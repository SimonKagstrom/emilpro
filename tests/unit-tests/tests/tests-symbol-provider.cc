#include "../test.hh"
#include "../symbol-fixture.hh"

#include <symbolfactory.hh>
#include <isymbolprovider.hh>
#include <idisassembly.hh>

#include <utils.hh>

using namespace emilpro;

TESTSUITE(symbol_provider)
{
	class ExecFixture : public SymbolFixture
	{
	public:
		void checkSymbols(std::string prefix = "")
		{
			ASSERT_TRUE(m_symbolNames.find(prefix + "main") != m_symbolNames.end());
			ASSERT_TRUE(m_symbolNames.find(prefix + "global_data") != m_symbolNames.end());

			ISymbol *sym = m_symbolNames[prefix + "main"];
			ASSERT_TRUE(sym != (void *)NULL);

			ASSERT_TRUE(sym->getType() == ISymbol::SYM_TEXT);
			ASSERT_TRUE(sym->getSize() > 1U);
			ASSERT_TRUE(sym->getDataPtr() != (void *)NULL);
			ASSERT_TRUE(sym->isWriteable() == false);
			ASSERT_TRUE(sym->isExecutable() == true);
			IDisassembly &dis = IDisassembly::instance();

			// Disassemble main()
			InstructionList_t insns = dis.execute(sym->getDataPtr(), sym->getSize(), sym->getAddress());
			ASSERT_TRUE(insns.size() > 0U);


			uint32_t v = 5;
			sym = m_symbolNames[prefix + "global_data"];
			ASSERT_TRUE(sym != (void *)NULL);
			ASSERT_TRUE(sym->getSize() == sizeof(uint32_t));
			ASSERT_TRUE(sym->getType() == ISymbol::SYM_DATA);
			ASSERT_TRUE(sym->isWriteable() == true);
			ASSERT_TRUE(sym->isExecutable() == false);
			ASSERT_TRUE(memcmp(sym->getDataPtr(), &v, sizeof(v)) == 0);

			v = 0;
			sym = m_symbolNames[prefix + "global_data_bss"];
			ASSERT_TRUE(sym != (void *)NULL);
			ASSERT_TRUE(sym->getSize() == sizeof(uint32_t));
			ASSERT_TRUE(sym->getType() == ISymbol::SYM_DATA);
			ASSERT_TRUE(sym->isWriteable() == true);
			ASSERT_TRUE(sym->isExecutable() == false);
			ASSERT_TRUE(memcmp(sym->getDataPtr(), &v, sizeof(v)) == 0);
		}
	};

	class DuplicateFixture : public ISymbolListener, public IRelocationListener
	{
	public:
		DuplicateFixture()
		{
			SymbolFactory::instance().registerListener(this, this);
		}

		virtual void onSymbol(ISymbol &sym)
		{
			m_symbolsByName[sym.getName()].push_back(&sym);
		}

		void onRelocation(IRelocation &reloc)
		{
		}

		std::unordered_map<std::string, std::list<ISymbol *>> m_symbolsByName;
	};

	TEST(nonPerfectMatches, SymbolFixture)
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

	TEST(validElf, ExecFixture)
	{
		SymbolFactory &factory = SymbolFactory::instance();
		unsigned res;

		size_t sz;
		void *data = read_file(&sz, "%s/test-binary", crpcut::get_start_dir());
		ASSERT_TRUE(data != (void *)NULL);

		res = factory.parseBestProvider(data, sz);
		ASSERT_TRUE(res > ISymbolProvider::NO_MATCH);

		ASSERT_TRUE(m_symbolNames.find(".text") != m_symbolNames.end());
		ISymbol *sym = m_symbolNames[".text"];
		ASSERT_TRUE(sym != (void *)NULL);
		ASSERT_TRUE(sym->getType() == ISymbol::SYM_SECTION);
		ASSERT_TRUE(sym->getAddress() != 0U);
		ASSERT_TRUE(sym->isAllocated() == true);
		ASSERT_TRUE(sym->isWriteable() == false);
		ASSERT_TRUE(sym->isExecutable() == true);
		ASSERT_TRUE(sym->getSize() > 0U);

		ASSERT_TRUE(m_symbolNames.find(".data") != m_symbolNames.end());
		sym = m_symbolNames[".data"];
		ASSERT_TRUE(sym != (void *)NULL);
		ASSERT_TRUE(sym->getType() == ISymbol::SYM_SECTION);
		ASSERT_TRUE(sym->getAddress() != 0U);
		ASSERT_TRUE(sym->isAllocated() == true);
		ASSERT_TRUE(sym->isWriteable() == true);
		ASSERT_TRUE(sym->isExecutable() == false);
		ASSERT_TRUE(sym->getSize() > 0U);

		ASSERT_TRUE(m_symbolNames.find("file") != m_symbolNames.end());
		sym = m_symbolNames["file"];
		ASSERT_TRUE(sym != (void *)NULL);
		ASSERT_TRUE(sym->getType() == ISymbol::SYM_FILE);
		ASSERT_TRUE(sym->getAddress() == 0U);
		ASSERT_TRUE(sym->getSize() == sz);

		checkSymbols();

		bool found = false;
		for (std::unordered_map<std::string, ISymbol *>::iterator it = m_symbolNames.begin();
				it != m_symbolNames.end();
				++it) {
			std::string name = it->first;

			if (name.find("start_main@plt") != std::string::npos)
				found = true;
		}

		ASSERT_TRUE(found);
	}

	TEST(valid32bitElf, ExecFixture)
	{
		SymbolFactory &factory = SymbolFactory::instance();
		unsigned res;

		size_t sz;
		void *data = read_file(&sz, "%s/test-binary-asm-only-32", crpcut::get_start_dir());
		ASSERT_TRUE(data != (void *)NULL);

		res = factory.parseBestProvider(data, sz);
		ASSERT_TRUE(res > ISymbolProvider::NO_MATCH);

		ISymbol *sym;

		sym = m_symbolNames["_start"];
		ASSERT_TRUE(sym != (void *)NULL);
		ASSERT_TRUE(sym->getSize() == 128U);
		ASSERT_TRUE(sym->getType() == ISymbol::SYM_TEXT);
	}

	TEST(validPE, ExecFixture)
	{
		SymbolFactory &factory = SymbolFactory::instance();
		unsigned res;

		size_t sz;
		void *data = read_file(&sz, "%s/test-binary.exe", crpcut::get_start_dir());
		ASSERT_TRUE(data != (void *)NULL);

		res = factory.parseBestProvider(data, sz);
		ASSERT_TRUE(res > ISymbolProvider::NO_MATCH);

		checkSymbols("_");
	}

	DISABLED_TEST(validMachO, ExecFixture)
	{
		SymbolFactory &factory = SymbolFactory::instance();
		unsigned res;

		size_t sz;
		void *data = read_file(&sz, "%s/test-binary.mach-o", crpcut::get_start_dir());
		ASSERT_TRUE(data != (void *)NULL);

		res = factory.parseBestProvider(data, sz);
		ASSERT_TRUE(res > ISymbolProvider::NO_MATCH);

		checkSymbols("_");
	}

	TEST(deduceSymbolSize, SymbolFixture)
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

	TEST(deduceLastSymbolSize, SymbolFixture)
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


	TEST(duplicateSymbols, DuplicateFixture)
	{
		SymbolFactory &factory = SymbolFactory::instance();
		unsigned res;

		size_t sz;
		void *data = read_file(&sz, "%s/test-binary", crpcut::get_start_dir());
		ASSERT_TRUE(data != (void *)NULL);

		res = factory.parseBestProvider(data, sz);
		ASSERT_TRUE(res > ISymbolProvider::NO_MATCH);

		ASSERT_TRUE(m_symbolsByName["main"].size() == 1);

		free(data);
		factory.destroy();
	}
}
