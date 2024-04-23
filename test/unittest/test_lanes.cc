/*
 * 
 */
#include "emilpro/jump_lanes.hh"
#include "emilpro/mock/mock_instruction.hh"
#include "test.h"

using namespace emilpro;

namespace
{

class Fixture
{
public:
    Fixture()
    {
        /*
         *  0:         je   2 ->
         *  1:         nop      |
         *  2:         nop    <-
         *  3:         nop
         *  4:         je  10 ----->
         *  5:         nop         |
         *  6:         je   8 -->  |
         *  7:         nop      |  |
         *  8:         nop    <-   |
         *  9:         nop         |
         * 10:      -> nop   <------
         * 11:    ->|  nop
         * 12:   |  |  nop
         * 13:   |   - je  10
         * 14:   <-    je  11
         */
        for (auto i = 0u; i < 15; i++)
        {
            auto cur = &instructions.back();

            expecations.push_back(
                NAMED_ALLOW_CALL(*cur, Type()).RETURN(IInstruction::InstructionType::kOther));
            expecations.push_back(NAMED_ALLOW_CALL(*cur, RefersTo()).RETURN(std::nullopt));
            expecations.push_back(NAMED_ALLOW_CALL(*cur, ReferredBy()).RETURN(no_referers));
            expecations.push_back(NAMED_ALLOW_CALL(*cur, Offset()).RETURN(i));
        }

        CreateReference(0, 2);
        CreateReference(4, 10);
        CreateReference(6, 8);
        CreateReference(13, 10);
        CreateReference(14, 11);
    }

    void CreateReference(size_t from_index, size_t to_index)
    {
        auto from = &instructions[from_index];
        auto to = &instructions[to_index];

        expecations.push_back(NAMED_ALLOW_CALL(*from, RefersTo())
                                  .RETURN(IInstruction::Referer {nullptr, to_index, nullptr}));
        expecations.push_back(NAMED_ALLOW_CALL(*to, ReferredBy())
                                  .RETURN(std::vector<IInstruction::Referer> {
                                      IInstruction::Referer {nullptr, from_index, nullptr}}));
        expecations.push_back(
            NAMED_ALLOW_CALL(*from, Type()).RETURN(IInstruction::InstructionType::kBranch));
    }

    std::array<mock::MockInstruction, 15> instructions;
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
    REQUIRE(std::ranges::equal(l[3].backward_lanes, std::array {T::kNone, T::kNone, T::kNone}));
    REQUIRE(std::ranges::equal(l[3].forward_lanes, std::array {T::kNone, T::kNone, T::kNone}));
}
