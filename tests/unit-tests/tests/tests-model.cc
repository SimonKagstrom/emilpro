#include "../test.hh"
#include "../symbol-fixture.hh"

#include "../../src/model.cc"
#include <utils.hh>
#include <architecturefactory.hh>
#include <instructionfactory.hh>
#include <configuration.hh>
#include <emilpro.hh>

using namespace emilpro;

#include "assembly-dumps.h"

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

	void addSymbol(uint64_t start, uint64_t end)
	{
		ASSERT_TRUE(m_listener);

		ISymbol &p = SymbolFactory::instance().createSymbol(ISymbol::LINK_NORMAL,
				ISymbol::SYM_TEXT,
				fmt("%llx..%llx\n", (long long)start, (long long)end).c_str(),
				NULL,
				start,
				end - start,
				true,
				true);

		m_listener->onSymbol(p);
	}

private:
	ISymbolListener *m_listener;
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

		res = model.addData(data, sz);
		ASSERT_TRUE(res == true);

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
		ArchitectureFactory::instance().provideArchitecture(bfd_arch_i386);

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

		model.parseAll();
		while (!model.parsingComplete())
			;

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

				if (strcmp(sym->getName(), "main") != 0)
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
}
