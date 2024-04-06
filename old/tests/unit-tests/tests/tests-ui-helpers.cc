#include "../test.hh"

#include <ui-helpers.hh>

#include "../mock-symbol-provider.hh"

using namespace emilpro;

TESTSUITE(ui_helpers)
{
	TEST(getBestSymbol)
	{
		MockSymbolProvider sp;
		uint8_t data;
		Model &model = Model::instance();
		bool res;

		res = model.addData((void *)&data, 1);
		ASSERT_TRUE(res == true);

		sp.addSymbol(0x1000, 0x4000, ISymbol::SYM_SECTION);
		sp.addSymbol(0x1000, 0x2000, ISymbol::SYM_TEXT);
		sp.addSymbol(0x2000, 0x2000, ISymbol::SYM_DATA);

		const ISymbol *sym;

		sym = UiHelpers::getBestSymbol(0x1000, "");
		ASSERT_TRUE(sym);

		ASSERT_TRUE(sym->getAddress() == 0x1000);
		ASSERT_TRUE(sym->getType() == ISymbol::SYM_TEXT);


		sym = UiHelpers::getBestSymbol(0x1010, "");
		ASSERT_TRUE(sym);

		ASSERT_TRUE(sym->getAddress() == 0x1000);
		ASSERT_TRUE(sym->getType() == ISymbol::SYM_TEXT);
	}
}
