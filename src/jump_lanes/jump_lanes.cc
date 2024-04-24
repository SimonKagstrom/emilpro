#include "emilpro/jump_lanes.hh"

using namespace emilpro;


void
JumpLanes::Calculate(unsigned max_distance,
                     std::span<const std::reference_wrapper<IInstruction>> instructions)
{
    Lanes lanes;

    m_lanes.clear();

    for (auto& insn_ref : instructions)
    {
        auto& insn = insn_ref.get();
        auto refers_to = insn.RefersTo();
        auto referenced_by = insn.ReferredBy();

        if (referenced_by.empty() == false && lanes.forward_lanes[0] == Type::kTraffic)
        {
            lanes.forward_lanes[0] = Type::kEnd;
        }
        if (lanes.forward_lanes[0] == Type::kStart)
        {
            lanes.forward_lanes[0] = Type::kTraffic;
        }
        if (refers_to && refers_to->offset > insn.Offset())
        {
            lanes.forward_lanes[0] = Type::kStart;
        }

        m_lanes.push_back(lanes);
    }
}

std::span<const JumpLanes::Lanes>
JumpLanes::GetLanes() const
{
    return m_lanes;
}
