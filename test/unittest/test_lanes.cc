/*
 * 
 */
#include "emilpro/jump_lanes.hh"
#include "emilpro/mock/mock_instruction.hh"
#include "test.h"

#include <fmt/format.h>

using namespace emilpro;

namespace
{

class Fixture
{
public:
    Fixture()
    {
        REQUIRE(instruction_refs.size() == instructions.size());

        /*
         *  0:             je   2 --.
         *  1:             nop      |
         *  2:             nop    <-
         *  3:             nop
         *  4:             je  10 -----.
         *  5:             nop         |
         *  6:             je   8 --.  |
         *  7: ,-------->  nop      |  |
         *  8: |    ->     nop      |  |
         *  9: |    |      nop    <-'  |
         * 10: |    |      nop   <-----'
         * 11: |  ->|- ->  nop
         * 12: | |  |  `-  je  11
         * 13: | |  `-     je   8
         * 14: | `-        je  11
         * 15: `---------- je   7
         */
        for (auto i = 0u; i < instructions.size(); i++)
        {
            auto& cur = instructions[i];

            expecations.push_back(
                NAMED_ALLOW_CALL(cur, Type()).RETURN(IInstruction::InstructionType::kOther));
            expecations.push_back(NAMED_ALLOW_CALL(cur, RefersTo()).RETURN(std::nullopt));
            expecations.push_back(NAMED_ALLOW_CALL(cur, ReferredBy()).RETURN(no_referers));
            expecations.push_back(NAMED_ALLOW_CALL(cur, Offset()).RETURN(i));
        }

        CreateReference(0, 2);
        CreateReference(4, 10);
        CreateReference(6, 9);
        // Backward
        CreateReference(12, 11);
        CreateReference(13, 8);
        CreateReference(14, 11);
        CreateReference(15, 7);
    }

    void CreateReference(size_t from_index, size_t to_index)
    {
        const auto& from = instructions[from_index];
        const auto& to = instructions[to_index];

        expecations.push_back(NAMED_ALLOW_CALL(from, RefersTo())
                                  .RETURN(IInstruction::Referer {nullptr, to_index, nullptr}));
        expecations.push_back(NAMED_ALLOW_CALL(to, ReferredBy())
                                  .RETURN(std::vector<IInstruction::Referer> {
                                      IInstruction::Referer {nullptr, from_index, nullptr}}));
        expecations.push_back(
            NAMED_ALLOW_CALL(from, Type()).RETURN(IInstruction::InstructionType::kBranch));
    }

    void PrintLanes(auto l)
    {
        int i = 0;
        for (auto insn : l)
        {
            fmt::print("Instruction {:2d}:  ", i);
            i++;
            for (auto backard : insn.backward_lanes)
            {
                fmt::print(" {}", static_cast<int>(backard));
            }
            fmt::print("   xxx  ");
            for (auto forward : insn.forward_lanes)
            {
                fmt::print(" {}", static_cast<int>(forward));
            }
            fmt::print("\n");
        }
    }

    std::array<mock::MockInstruction, 16> instructions;
    std::vector<std::reference_wrapper<IInstruction>> instruction_refs {instructions.begin(),
                                                                        instructions.end()};
    JumpLanes lanes;

private:
    std::vector<IInstruction::Referer> no_referers;
    std::vector<std::unique_ptr<trompeloeil::expectation>> expecations;
};

} // namespace

using T = JumpLanes::Type;

TEST_CASE_FIXTURE(Fixture, "there are no lanes for instructions where no jumps pass")
{
    REQUIRE(lanes.GetLanes().empty());
    lanes.Calculate(16, instruction_refs);

    auto l = lanes.GetLanes();
    REQUIRE(l.size() == instructions.size());
    REQUIRE(std::ranges::equal(l[3].forward_lanes,
                               std::array {T::kNone, T::kNone, T::kNone, T::kNone}));
    REQUIRE(std::ranges::equal(l[3].backward_lanes,
                               std::array {T::kNone, T::kNone, T::kNone, T::kNone}));
}

TEST_CASE_FIXTURE(Fixture, "a single lane is used for a solitary jump")
{
    lanes.Calculate(16, instruction_refs);

    auto l = lanes.GetLanes();

    // 0..2
    REQUIRE(l[0].forward_lanes[0] == T::kStart);
    REQUIRE(l[1].forward_lanes[0] == T::kTraffic);
    REQUIRE(l[2].forward_lanes[0] == T::kEnd);
}

TEST_CASE_FIXTURE(Fixture, "a short maximum size is handled")
{
    lanes.Calculate(3, instruction_refs);

    auto l = lanes.GetLanes();

    // 0..2, short jump
    THEN("short jumps use lanes")
    {
        REQUIRE(l[0].forward_lanes[0] == T::kStart);
        REQUIRE(l[1].forward_lanes[0] == T::kTraffic);
        REQUIRE(l[2].forward_lanes[0] == T::kEnd);
    }

    THEN("long jumps use only start/end")
    {
        // 4..10, long jump
        REQUIRE(l[4].forward_lanes[0] == T::kLongStart);
        REQUIRE(l[5].forward_lanes[1] == T::kNone);
        REQUIRE(l[5].forward_lanes[2] == T::kNone);
        REQUIRE(l[5].forward_lanes[3] == T::kNone);
        REQUIRE(l[10].forward_lanes[0] == T::kLongEnd);
    }
}

TEST_CASE_FIXTURE(Fixture, "dual lanes are used for enclosing jumps")
{
    lanes.Calculate(16, instruction_refs);

    auto l = lanes.GetLanes();

    // 4..10
    REQUIRE(l[4].forward_lanes[1] == T::kStart);
    for (auto i = 5u; i < 10; i++)
    {
        REQUIRE(l[i].forward_lanes[1] == T::kTraffic);
    }
    REQUIRE(l[10].forward_lanes[1] == T::kEnd);

    // 6..8, enclosed
    REQUIRE(l[6].forward_lanes[0] == T::kStart);
    REQUIRE(l[7].forward_lanes[0] == T::kTraffic);
    REQUIRE(l[9].forward_lanes[0] == T::kEnd);
}

TEST_CASE_FIXTURE(Fixture, "backward lanes are also handled")
{
    lanes.Calculate(16, instruction_refs);
    PrintLanes(lanes.GetLanes());

    auto l = lanes.GetLanes();
    REQUIRE(l[11].backward_lanes[0] == T::kEnd);
    REQUIRE(l[12].backward_lanes[0] == T::kStart);

    REQUIRE(l[8].backward_lanes[1] == T::kEnd);
    REQUIRE(l[13].backward_lanes[1] == T::kStart);

    REQUIRE(l[11].backward_lanes[2] == T::kEnd);
    REQUIRE(l[14].backward_lanes[2] == T::kStart);

    REQUIRE(l[7].backward_lanes[3] == T::kEnd);
    REQUIRE(l[15].backward_lanes[3] == T::kStart);
}
