#include "../test.hh"

#include <model.hh>
#include <emilpro.hh>
#include <utils.hh>

#include <addresshistory.hh>

#include "../mock-symbol-provider.hh"

using namespace emilpro;

TESTSUITE(address_history)
{
	TEST(invalid_add)
	{
		ASSERT_SCOPE_HEAP_LEAK_FREE
		{
			AddressHistory h;
			bool res;

			// We've not added anything yet, so it should be empty;
			res = h.maybeAddEntry(0);
			ASSERT_FALSE(res);

			EmilPro::destroy();
		}
	}

	TEST(valid_add, SymbolFixture)
	{
		// Something is rotten in unordered_map
		//ASSERT_SCOPE_HEAP_LEAK_FREE
		{
			MockSymbolProvider *symProvider = new MockSymbolProvider();
			AddressHistory h;
			bool res;
			uint8_t data;
			Model &model = Model::instance();

			res = model.addData((void *)&data, 1);
			ASSERT_TRUE(res == true);

			symProvider->addSymbol(1, 2);

			res = h.maybeAddEntry(1);
			ASSERT_TRUE(res);

			const AddressHistory::Entry &e = h.current();
			ASSERT_TRUE(e.isValid());
			ASSERT_TRUE(e.getAddress() == 1U);

			const AddressHistory::Entry &eb = h.back();
			ASSERT_FALSE(eb.isValid());

			const AddressHistory::Entry &ef = h.forward();
			ASSERT_FALSE(ef.isValid());

			EmilPro::destroy();
		}
	}

	TEST(multiple_adds, SymbolFixture)
	{
		//ASSERT_SCOPE_HEAP_LEAK_FREE
		{
			MockSymbolProvider *symProvider = new MockSymbolProvider();
			AddressHistory h;
			bool res;
			uint8_t data;
			Model &model = Model::instance();

			res = model.addData((void *)&data, 1);
			ASSERT_TRUE(res == true);

			symProvider->addSymbol(1, 2);
			symProvider->addSymbol(3, 5);

			res = h.maybeAddEntry(1);
			ASSERT_TRUE(res);

			const AddressHistory::Entry &e = h.current();
			ASSERT_TRUE(e.isValid());
			ASSERT_TRUE(e.getAddress() == 1U);

			res = h.maybeAddEntry(3);
			ASSERT_TRUE(res);

			const AddressHistory::Entry &e2 = h.current();
			ASSERT_TRUE(e2.isValid());
			ASSERT_TRUE(e2.getAddress() == 3U);

			const AddressHistory::Entry &eb = h.back();
			ASSERT_TRUE(eb.isValid());
			ASSERT_TRUE(eb.getAddress() == 1U);

			const AddressHistory::Entry &eb2 = h.back();
			ASSERT_FALSE(eb2.isValid());

			const AddressHistory::Entry &ef = h.forward();
			ASSERT_TRUE(ef.isValid());
			ASSERT_TRUE(ef.getAddress() == 3U);

			const AddressHistory::Entry &ef2 = h.forward();
			ASSERT_FALSE(ef2.isValid());

			EmilPro::destroy();
		}
	}

	TEST(iterate_in_middle, SymbolFixture)
	{
		//ASSERT_SCOPE_HEAP_LEAK_FREE
		{
			MockSymbolProvider *symProvider = new MockSymbolProvider();
			AddressHistory h;
			bool res;
			uint8_t data;
			Model &model = Model::instance();

			res = model.addData((void *)&data, 1);
			ASSERT_TRUE(res == true);

			symProvider->addSymbol(1, 2);
			symProvider->addSymbol(3, 5);
			symProvider->addSymbol(6, 7);
			symProvider->addSymbol(9, 10);

			res = h.maybeAddEntry(1);
			ASSERT_TRUE(res);
			res = h.maybeAddEntry(3);
			ASSERT_TRUE(res);
			res = h.maybeAddEntry(6);
			ASSERT_TRUE(res);

			const AddressHistory::Entry &e = h.current();
			ASSERT_TRUE(e.isValid());
			ASSERT_TRUE(e.getAddress() == 6U);

			const AddressHistory::Entry &eb = h.back();
			ASSERT_TRUE(eb.isValid());
			ASSERT_TRUE(eb.getAddress() == 3U);

			// Current should stay at 3
			res = h.maybeAddEntry(9);
			ASSERT_TRUE(res);

			const AddressHistory::Entry &ec = h.current();
			ASSERT_TRUE(ec.isValid());
			ASSERT_TRUE(ec.getAddress() == 3U);

			EmilPro::destroy();
		}
	}
}
