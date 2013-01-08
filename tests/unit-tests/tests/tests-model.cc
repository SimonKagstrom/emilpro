#include "../test.hh"
#include "../symbol-fixture.hh"

#include "../../src/model.cc"
#include <utils.hh>

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

	TEST(memLeaks, SymbolFixture)
	{
		ASSERT_SCOPE_HEAP_LEAK_FREE
		{
			Model &model = Model::instance();
			IDisassembly &dis = IDisassembly::instance();

			InstructionList_t lst = dis.execute((void *)ia32_dump, sizeof(ia32_dump), 0x1000);
			Model::BasicBlockList_t bbLst = model.getBasicBlocksFromInstructions(lst);
			ASSERT_TRUE(bbLst.size() == 5U);

			model.destroy();
			SymbolFactory::instance().destroy();
			IDisassembly::instance().destroy();
		}
	}
}
