#include "../test.hh"
#include "../symbol-fixture.hh"

#include "../../src/model.cc"
#include <utils.hh>
#include <architecturefactory.hh>
#include <instructionfactory.hh>
#include <configuration.hh>
#include <emilpro.hh>

#include <list>
#include <unordered_map>

using namespace emilpro;

#include "assembly-dumps.h"
#include "../mock-symbol-provider.hh"

class ModelSymbolFixture : public ISymbolListener
{
public:
	void onSymbol(ISymbol &sym)
	{
		m_symbols.push_back(&sym);
		m_symbolsByName[sym.getName()] = &sym;
	}

	void clear()
	{
		m_symbols.clear();
		m_symbolsByName.clear();
	}

	Model::SymbolList_t m_symbols;
	std::unordered_map<std::string, ISymbol *> m_symbolsByName;
};


TESTSUITE(model)
{
	TEST(lookupSymbols, SymbolFixture)
	{
		Model &model = Model::instance();
		bool res;


		size_t sz;
		void *data = read_file(&sz, "%s/test-binary", crpcut::get_start_dir());
		ASSERT_TRUE(data != (void *)NULL);

		ASSERT_TRUE(model.getArchitecture() == bfd_arch_unknown);
		res = model.addData(data, sz);
		ASSERT_TRUE(res == true);
		ASSERT_TRUE(model.getArchitecture() == bfd_arch_i386);

		ISymbol *sym = m_symbolNames["main"];
		ASSERT_TRUE(sym != (void *)NULL);

		Model::SymbolList_t other = model.getSymbolExact(sym->getAddress());
		ASSERT_TRUE(other.size() == 1U);
		ASSERT_TRUE(other.front() == sym);

		other = model.getNearestSymbol(sym->getAddress() + 8);
		ASSERT_TRUE(other.size() == 1U);
		ASSERT_TRUE(other.front() == sym);

		sym = m_symbolNames["asm_sym2"];
		if (!sym)
			sym = m_symbolNames["asm_sym3"];
		ASSERT_TRUE(sym);

		Model::SymbolList_t syms = model.getSymbolExact(sym->getAddress());
		ASSERT_TRUE(syms.size() == 2U); // asm_sym3 as well
	}

	TEST(lookupSymbolsNearest, SymbolFixture)
	{
		MockSymbolProvider *symProvider = new MockSymbolProvider();

		Model &model = Model::instance();
		bool res;

		uint8_t data;

		res = model.addData((void *)&data, 1);
		ASSERT_TRUE(res == true);

		symProvider->addSymbol(10, 19);
		symProvider->addSymbol(20, 29);
		symProvider->addSymbol(30, 39);
		symProvider->addSymbol(30, 34); // Two at the same address
		symProvider->addSymbol(50, 59); // Some space between

		Model::SymbolList_t sym;

		sym = model.getSymbolExact(10); ASSERT_TRUE(sym.size() == 1U);
		ASSERT_TRUE(sym.front()->getAddress() == 10U);
		sym = model.getSymbolExact(20);	ASSERT_TRUE(sym.size() == 1U);
		ASSERT_TRUE(sym.front()->getAddress() == 20U);
		sym = model.getSymbolExact(30);	ASSERT_TRUE(sym.size() == 2U);
		ASSERT_TRUE(sym.front()->getAddress() == 30U);
		sym = model.getSymbolExact(50);	ASSERT_TRUE(sym.size() == 1U);
		ASSERT_TRUE(sym.front()->getAddress() == 50U);

		sym = model.getSymbolExact(11);
		ASSERT_TRUE(sym.empty());
		sym = model.getSymbolExact(9);
		ASSERT_TRUE(sym.empty());


		sym = model.getNearestSymbol(10);
		ASSERT_TRUE(sym.size() == 1U);
		ASSERT_TRUE(sym.front()->getAddress() == 10U);

		// No symbols
		sym = model.getNearestSymbol(60);
		ASSERT_TRUE(sym.empty());
		sym = model.getNearestSymbol(9);
		ASSERT_TRUE(sym.empty());
		sym = model.getNearestSymbol(40);
		ASSERT_TRUE(sym.empty());


		sym = model.getNearestSymbol(11); ASSERT_TRUE(sym.size() == 1U);
		ASSERT_TRUE(sym.front()->getAddress() == 10U);
		sym = model.getNearestSymbol(29); ASSERT_TRUE(sym.size() == 1U);
		ASSERT_TRUE(sym.front()->getAddress() == 20U);
		sym = model.getNearestSymbol(31); ASSERT_TRUE(sym.size() == 2U);
		ASSERT_TRUE(sym.front()->getAddress() == 30U);
		sym = model.getNearestSymbol(35); ASSERT_TRUE(sym.size() == 1U);
		ASSERT_TRUE(sym.front()->getAddress() == 30U);
		sym = model.getNearestSymbol(51); ASSERT_TRUE(sym.size() == 1U);
		ASSERT_TRUE(sym.front()->getAddress() == 50U);
	}

	TEST(disassembleInstructions, SymbolFixture)
	{
		Model &model = Model::instance();
		bool res;

		size_t sz;
		void *data = read_file(&sz, "%s/test-binary", crpcut::get_start_dir());
		ASSERT_TRUE(data != (void *)NULL);

		res = model.addData(data, sz);
		ASSERT_TRUE(res == true);

		ISymbol *sym = m_symbolNames["main"];
		ASSERT_TRUE(sym != (void *)NULL);

		ASSERT_TRUE(model.m_instructionCache.find(sym->getAddress()) == model.m_instructionCache.end());
		InstructionList_t lst = model.getInstructions(sym->getAddress(), sym->getAddress() + sym->getSize());
		sz = lst.size();
		ASSERT_TRUE(sz > 0U);
		// We should now have this in the cache
		ASSERT_TRUE(model.m_instructionCache.find(sym->getAddress()) != model.m_instructionCache.end());

		// Misaligned (should still work)
		lst = model.getInstructions(sym->getAddress() + 1, sym->getAddress() + sym->getSize() - 1);
		ASSERT_TRUE(lst.size() > 0U);
		ASSERT_TRUE(lst.size() < sz);

		model.destroy();
	};


	TEST(generateBasicBlocks, SymbolFixture)
	{
		EmilPro::init();
		ArchitectureFactory::instance().provideArchitecture(bfd_arch_i386, bfd_mach_i386_i386);

		Model &model = Model::instance();
		IDisassembly &dis = IDisassembly::instance();

		InstructionList_t lst = dis.execute((void *)ia32_dump, sizeof(ia32_dump), 0x1000);
		ASSERT_TRUE(lst.size() == 11U);

		Model::BasicBlockList_t bbLst = model.getBasicBlocksFromInstructions(lst);
		ASSERT_TRUE(bbLst.size() == 5U);

		Model::IBasicBlock *first = bbLst.front();
		Model::IBasicBlock *last = bbLst.back();

		ASSERT_TRUE(first->getInstructions().front()->getMnemonic() == "jbe");
		ASSERT_TRUE(first->getInstructions().back()->getMnemonic() == "jbe");
		ASSERT_TRUE(last->getInstructions().front()->getMnemonic() == "mov");
		ASSERT_TRUE(last->getInstructions().back()->getMnemonic() == "mov");

		model.destroy();
	};

	TEST(sourceLines, SymbolFixture)
	{
		Model &model = Model::instance();
		bool res;

		size_t sz;
		void *data = read_file(&sz, "%s/test-binary", crpcut::get_start_dir());
		ASSERT_TRUE(data != (void *)NULL);

		res = model.addData(data, sz);
		ASSERT_TRUE(res == true);

		ISymbol *sym = m_symbolNames["main"];
		ASSERT_TRUE(sym != (void *)NULL);

		ASSERT_TRUE(model.m_fileLineCache.empty() == true);
		InstructionList_t lst = model.getInstructions(sym->getAddress(), sym->getAddress() + sym->getSize());
		sz = lst.size();
		ASSERT_TRUE(sz > 0U);

		bool foundMain15 = false; // Empty line (should not be found)
		bool foundMain14 = false; // kalle(); at line 14 in elf-example-source.c
		for (InstructionList_t::iterator it = lst.begin();
				it != lst.end();
				++it) {
			IInstruction *cur = *it;
			ILineProvider::FileLine fileLine = model.getLineByAddress(cur->getAddress());

			if (!fileLine.m_isValid)
				continue;

			if (fileLine.m_file.find("elf-example-source.c") == std::string::npos)
				continue;

			if (fileLine.m_lineNr == 14)
				foundMain14 = true;
			else if (fileLine.m_lineNr == 15)
				foundMain15 = true;
		}

		ASSERT_TRUE(model.m_fileLineCache.empty() == false);
		ASSERT_TRUE(foundMain15 == false);
		ASSERT_TRUE(foundMain14 == true);

		// Rerun to test the cache
		foundMain14 = false;
		foundMain15 = false;
		for (InstructionList_t::iterator it = lst.begin();
				it != lst.end();
				++it) {
			IInstruction *cur = *it;
			ILineProvider::FileLine fileLine = model.getLineByAddress(cur->getAddress());

			if (!fileLine.m_isValid)
				continue;

			if (fileLine.m_file.find("elf-example-source.c") == std::string::npos)
				continue;

			if (fileLine.m_lineNr == 14)
				foundMain14 = true;
			else if (fileLine.m_lineNr == 15)
				foundMain15 = true;
		}
		ASSERT_TRUE(foundMain15 == false);
		ASSERT_TRUE(foundMain14 == true);

		model.destroy();
	}

	TEST(workerThreads, SymbolFixture)
	{
		Model &model = Model::instance();
		size_t sz;
		bool res;

		void *data = read_file(&sz, "%s/test-binary", crpcut::get_start_dir());
		ASSERT_TRUE(data != (void *)NULL);

		res = model.addData(data, sz);
		ASSERT_TRUE(res == true);

		ISymbol *mainSym = m_symbolNames["main"];
		ASSERT_TRUE(mainSym);
		ASSERT_TRUE(!model.m_instructionCache[mainSym->getAddress()]);

		ASSERT_TRUE(!model.parsingComplete());
		ASSERT_FALSE(model.parsingOngoing());

		model.parseAll();
		ASSERT_TRUE(model.parsingOngoing()); // Slight race, but should be OK
		while (!model.parsingComplete())
			;

		ASSERT_FALSE(model.parsingOngoing());
		ASSERT_TRUE(model.parsingComplete());
		ASSERT_TRUE(model.m_instructionCache[mainSym->getAddress()]);
	}

	TEST(crossReferences, SymbolFixture)
	{
		EmilPro::init();

		Model &model = Model::instance();
		size_t sz;
		bool res;

		void *data = read_file(&sz, "%s/test-binary", crpcut::get_start_dir());
		ASSERT_TRUE(data != (void *)NULL);

		res = model.addData(data, sz);
		ASSERT_TRUE(res == true);

		model.parseAll();
		while (!model.parsingComplete())
			;

		Model::SymbolList_t syms = model.getSymbolExact(m_symbolNames["kalle"]->getAddress());
		ASSERT_TRUE(syms.size() == 1U);
		ASSERT_TRUE(model.getReferences(syms.front()->getAddress()).size() == 2U);

		syms = model.getSymbolExact(m_symbolNames["knatte"]->getAddress());
		ASSERT_TRUE(syms.size() == 1U);
		ASSERT_TRUE(model.getReferences(syms.front()->getAddress()).size() == 0U);
	}

	TEST(fileWithSymbols, ModelSymbolFixture)
	{
		// I'd like to run this with ASSERT_SCOPE_HEAP_LEAK_FREE, but I run into
		// glib memleaks that way...

		Model &model = Model::instance();
		size_t sz;
		bool res;

		void *data = read_file(&sz, "%s/test-binary", crpcut::get_start_dir());
		ASSERT_TRUE(data != (void *)NULL);

		res = model.addData(data, sz);
		ASSERT_TRUE(res == true);

		model.registerSymbolListener(this);

		model.parseAll();

		// Busy wait until everything has been read
		while (!model.parsingComplete())
			;

		const Model::SymbolList_t &syms = model.getSymbols();

		ASSERT_TRUE(syms.size() > 0U);
		ASSERT_TRUE(syms.size() <= m_symbols.size());

		EmilPro::destroy();

		free((void *)data);
	}

	TEST(fileWithoutSymbols, ModelSymbolFixture)
	{
		EmilPro::init();

		Model &model = Model::instance();
		size_t sz;
		bool res;
		void *data;

		data = read_file(&sz, "%s/test-binary", crpcut::get_start_dir());
		res = model.addData(data, sz);
		ASSERT_TRUE(res == true);

		model.registerSymbolListener(this);

		// Parse and wait
		model.parseAll();
		while (!model.parsingComplete())
			;

		std::string fnName = "kalle";
		ISymbol *fnSym = m_symbolsByName[fnName];
		ASSERT_TRUE(fnSym);
		uint64_t fnAddr = fnSym->getAddress();
		uint64_t fnSize = fnSym->getSize();
		ASSERT_TRUE(fnAddr != 0U);

		EmilPro::destroy();
		free((void *)data);
		clear();

		// Recreate the model
		EmilPro::init();
		Model &model2 = Model::instance();

		data = read_file(&sz, "%s/test-binary-stripped", crpcut::get_start_dir());
		res = model2.addData(data, sz);
		ASSERT_TRUE(res == true);

		model2.registerSymbolListener(this);

		// Parse and wait
		model2.parseAll();
		while (!model2.parsingComplete())
			;

		bool foundFn = false;
		for (Model::SymbolList_t::iterator it = m_symbols.begin();
				it != m_symbols.end();
				++it) {
			ISymbol *cur = *it;

			if (cur->getAddress() == fnAddr) {
				printf("Found derived function at 0x%llx with name %s and size %lld, original %s/%lld\n",
						(unsigned long long)cur->getAddress(), cur->getName().c_str(), (long long)cur->getSize(),
						fnName.c_str(), (long long)fnSize);
				foundFn = true;
			}
		}
		ASSERT_TRUE(foundFn);
	}

	TEST(memLeaks)
	{
		ASSERT_SCOPE_HEAP_LEAK_FREE
		{
			Model &model = Model::instance();
			size_t sz;
			bool res;

			void *data = read_file(&sz, "%s/test-binary", crpcut::get_start_dir());
			ASSERT_TRUE(data != (void *)NULL);

			res = model.addData(data, sz);
			ASSERT_TRUE(res == true);

			const Model::SymbolList_t &syms = model.getSymbols();

			InstructionList_t lst;
			for (Model::SymbolList_t::const_iterator it = syms.begin();
					it != syms.end();
					++it) {
				ISymbol *sym = *it;

				if (sym->getName() != "main")
					continue;

				lst = model.getInstructions(sym->getAddress(), sym->getAddress() + sym->getSize());
			}
			sz = lst.size();
			ASSERT_TRUE(sz > 0U);

			bool foundMain14 = false; // kalle(); at line 14 in elf-example-source.c
			for (InstructionList_t::iterator it = lst.begin();
					it != lst.end();
					++it) {
				IInstruction *cur = *it;
				ILineProvider::FileLine fileLine = model.getLineByAddress(cur->getAddress());

				if (!fileLine.m_isValid)
					continue;

				if (fileLine.m_file.find("elf-example-source.c") == std::string::npos)
					continue;

				if (fileLine.m_lineNr == 14)
					foundMain14 = true;
			}

			ASSERT_TRUE(foundMain14 == true);

//			Model::BasicBlockList_t bbLst = model.getBasicBlocksFromInstructions(lst);
//			ASSERT_TRUE(bbLst.size() > 0);

			EmilPro::destroy();

			free(data);
		}
	}

	TEST(empty)
	{
		Model &model = Model::instance();

		Model::SymbolList_t l;

		l = model.getNearestSymbol(0);
		ASSERT_TRUE(l.empty());

		l = model.getSymbolExact(0);
		ASSERT_TRUE(l.empty());
	}

	TEST(dataContents, ModelSymbolFixture)
	{
		EmilPro::init();

		Model &model = Model::instance();
		size_t sz;
		bool res;
		void *data;

		data = read_file(&sz, "%s/test-binary", crpcut::get_start_dir());
		res = model.addData(data, sz);
		ASSERT_TRUE(res == true);

		model.registerSymbolListener(this);

		// Parse and wait
		model.parseAll();
		while (!model.parsingComplete())
			;

		std::string dataName = "global_data";
		ISymbol *dataSym = m_symbolsByName[dataName];
		ASSERT_TRUE(dataSym);
		uint64_t addr = dataSym->getAddress();
		uint64_t size = dataSym->getSize();
		ASSERT_TRUE(addr != 0U);
		ASSERT_TRUE(size == sizeof(uint32_t));

		uint8_t buf[4];
		res = model.copyData(buf, addr, 4, NULL, NULL);
		ASSERT_TRUE(res);
		const uint32_t *asInt = (const uint32_t *)buf;

		ASSERT_TRUE(*asInt == 5U);

		// Out-of-bounds
		res = model.copyData(buf, 0, 4, NULL, NULL);
		ASSERT_FALSE(res);

		EmilPro::destroy();
	}

	TEST(getSurroundingData)
	{
		EmilPro::init();

		Model &model = Model::instance();

		uint8_t d1[8192];
		uint8_t d2[8192];

		uint64_t base = 0x10000;

		memset(d1, 'A', sizeof(d1));
		memset(d2, 'B', sizeof(d2));

		ISymbol &s1 = SymbolFactory::instance().createSymbol(ISymbol::LINK_NORMAL,
				ISymbol::SYM_SECTION,
				"D1\n",
				(void *)d1,
				base,
				sizeof(d1),
				true,
				false,
				true);

		// Create with a gap between
		ISymbol &s2 = SymbolFactory::instance().createSymbol(ISymbol::LINK_NORMAL,
				ISymbol::SYM_SECTION,
				"D2\n",
				(void *)d2,
				base + sizeof(d1) + 1024,
				sizeof(d2),
				true,
				false,
				true);

		// Add to the model
		model.onSymbol(s1);
		model.onSymbol(s2);

		const uint8_t *p;
		uint64_t addr = 0;
		uint64_t end = 0;

		p = model.getSurroundingData(base, 4096, &addr, &end);
		ASSERT_TRUE(p);
		ASSERT_TRUE(addr == base);
		ASSERT_TRUE(end == base + 2048U);

		p = model.getSurroundingData(base + 1024, 4096, &addr, &end);
		ASSERT_TRUE(p);
		ASSERT_TRUE(addr == base);
		ASSERT_TRUE(end == base + 1024U + 2048U);

		p = model.getSurroundingData(base + 8192 - 1024, 4096, &addr, &end);
		ASSERT_TRUE(p);
		ASSERT_TRUE(addr == base + 8192U - 4096U + 1024U);
		ASSERT_TRUE(end == base + 8192U);

		// Second area
		p = model.getSurroundingData(base + 8192 + 2048, 4096, &addr, &end);
		ASSERT_TRUE(p);
		ASSERT_TRUE(addr == base + 8192U + 1024U);
		ASSERT_TRUE(end == base + 8192U + 1024U + 2048U + 1024U);

		// Before
		p = model.getSurroundingData(0, 4096, &addr, &end);
		ASSERT_FALSE(p);
		// Above
		p = model.getSurroundingData(base + 8192 + 1024 + 8192 + 10, 4096, &addr, &end);
		ASSERT_FALSE(p);
		// Between
		p = model.getSurroundingData(base + 8192 + 10, 4096, &addr, &end);
		ASSERT_FALSE(p);

		EmilPro::destroy();
	}

	TEST(lookupAddresses)
	{
		EmilPro::init();

		Model &model = Model::instance();
		uint64_t base = 0xa000;

		ISymbol &s1 = SymbolFactory::instance().createSymbol(ISymbol::LINK_NORMAL,
				ISymbol::SYM_SECTION,
				"kalle",
				NULL,
				base,
				0x1000,
				true,
				false,
				true);

		// Create with a gap between
		ISymbol &s2 = SymbolFactory::instance().createSymbol(ISymbol::LINK_NORMAL,
				ISymbol::SYM_SECTION,
				"svenne",
				NULL,
				base + 0x2000,
				0x1000,
				true,
				false,
				true);


		ISymbol &s3 = SymbolFactory::instance().createSymbol(ISymbol::LINK_NORMAL,
				ISymbol::SYM_SECTION,
				"konny",
				NULL,
				base + 0x3000,
				0x1000,
				true,
				false,
				true);

		// Add to the model
		model.onSymbol(s1);
		model.onSymbol(s2);
		model.onSymbol(s3);

		Model::AddressList_t lst;

		lst = model.lookupAddressesByText("0x0");
		ASSERT_TRUE(lst.empty());
		lst = model.lookupAddressesByText("0xa000u"); // Will look like a name
		ASSERT_TRUE(lst.empty());
		lst = model.lookupAddressesByText("0xa000");
		ASSERT_TRUE(lst.size() == 1U);
		ASSERT_TRUE(lst.front() == 0xa000ULL);

		lst = model.lookupAddressesByText("0xa040 0xc030");
		ASSERT_TRUE(lst.size() == 2U);
		ASSERT_TRUE(lst.front() == 0xa040ULL);
		ASSERT_TRUE(lst.back() == 0xc030ULL);

		lst = model.lookupAddressesByText("kalle");
		ASSERT_TRUE(lst.size() == 1u);
		ASSERT_TRUE(lst.front() == 0xa000u);

		lst = model.lookupAddressesByText("kalle svenne+30");
		ASSERT_TRUE(lst.size() == 2u);
		ASSERT_TRUE(lst.front() == 0xa000u);
		ASSERT_TRUE(lst.back() == 0xc030u);

		lst = model.lookupAddressesByText("konny+0x24/96 konny+0xpalle");
		ASSERT_TRUE(lst.size() == 2u);
		ASSERT_TRUE(lst.front() == 0xd024u);
		ASSERT_TRUE(lst.back() == 0xd000u);

		EmilPro::destroy();
	}
}
