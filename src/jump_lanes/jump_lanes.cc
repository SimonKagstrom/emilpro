#include "emilpro/jump_lanes.hh"

using namespace emilpro;


void
JumpLanes::Calculate(unsigned max_distance,
                     std::span<const std::reference_wrapper<IInstruction>> instructions)
{
    m_lanes.clear();

    for (auto& insn_ref : instructions)
    {
        auto& insn = insn_ref.get();

        m_lanes.push_back(Lanes {.backward_lanes = {Type::kNone, Type::kNone, Type::kNone},
                                 .forward_lanes = {Type::kNone, Type::kNone, Type::kNone}});
    }
}

std::span<const JumpLanes::Lanes>
JumpLanes::GetLanes() const
{
    return m_lanes;
}
