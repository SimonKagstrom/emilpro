#include "../test.hh"
#include "../symbol-fixture.hh"

#include "../../src/model.cc"
#include <utils.hh>

using namespace emilpro;


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
}
