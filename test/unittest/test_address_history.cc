#include "emilpro/address_history.hh"
#include "emilpro/mock/mock_section.hh"
#include "test.h"

using namespace emilpro;

namespace
{

class Fixture
{
public:
    AddressHistory history;
    mock::MockSection section;
    mock::MockSection section2;
};

} // namespace

TEST_CASE_FIXTURE(Fixture, "the address history is initially empty")
{
    REQUIRE(history.Entries().empty());
}

TEST_CASE_FIXTURE(Fixture, "an entry can be pushed to the address history")
{
    history.PushEntry(section, 13);
    REQUIRE(history.CurrentIndex() == 0);
    REQUIRE(history.Entries()[0] == AddressHistory::Entry {&section, 13});
}

TEST_CASE_FIXTURE(Fixture, "entries can be selected in the middle of the history")
{
    history.PushEntry(section, 13);
    history.PushEntry(section2, 14);
    history.PushEntry(section, 15);

    REQUIRE(history.CurrentIndex() == 2);
    REQUIRE(history.Entries()[0] == AddressHistory::Entry {&section, 13});
    REQUIRE(history.Entries()[1] == AddressHistory::Entry {&section2, 14});
    REQUIRE(history.Entries()[2] == AddressHistory::Entry {&section, 15});

    WHEN("the first entry is selected")
    {
        history.SetIndex(1);
        REQUIRE(history.CurrentIndex() == 1);

        THEN("a newly pushed entry removes the second")
        {
            history.PushEntry(section, 99);
            REQUIRE(history.Entries().size() == 2);
            REQUIRE(history.Entries()[0] == AddressHistory::Entry {&section, 13});
            REQUIRE(history.Entries()[1] == AddressHistory::Entry {&section, 99});
        }
    }
}
