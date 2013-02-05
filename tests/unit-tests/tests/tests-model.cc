#include "../test.hh"
#include "../symbol-fixture.hh"

#include "../../src/model.cc"
#include <utils.hh>
#include <architecturefactory.hh>

using namespace emilpro;

#include "assembly-dumps.h"

TESTSUITE(model)
{
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

		InstructionList_t lst = model.getInstructions(sym->getAddress(), sym->getAddress() + sym->getSize());
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

		model.destroy();
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

			ASSERT_TRUE(foundMain15 == false);
			ASSERT_TRUE(foundMain14 == true);

//			Model::BasicBlockList_t bbLst = model.getBasicBlocksFromInstructions(lst);
//			ASSERT_TRUE(bbLst.size() > 0);

			model.destroy();
			SymbolFactory::instance().destroy();
			IDisassembly::instance().destroy();
			ArchitectureFactory::instance().destroy();

			free(data);
		}
	}
}
