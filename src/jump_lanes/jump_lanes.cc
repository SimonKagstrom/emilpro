#include "emilpro/jump_lanes.hh"

using namespace emilpro;


void
JumpLanes::Calculate(unsigned max_distance,
                     std::span<const std::reference_wrapper<IInstruction>> instructions)
{
    Lanes lanes;

    m_lanes.clear();

    /*
     * Rules:
     *
     * - Max 3 lanes
     * - Longer branches are pushed out (shorter on the closest lanes)
     * - Crossing branches are pushed out
     */
    for (auto& insn_ref : instructions)
    {
        auto& insn = insn_ref.get();
        auto refers_to = insn.RefersTo();
        auto referenced_by = insn.ReferredBy();

        if (refers_to && Distance(insn, *refers_to) <= max_distance)
        {
            if (insn.Offset() < refers_to->offset)
            {
                m_forward_lanes.push_back(Lane(insn.Offset(), refers_to->offset));
            }
        }
    }

    if (m_forward_lanes.empty())
    {
        m_lanes.resize(instructions.size());
        return;
    }

    auto it = m_forward_lanes.begin();
    for (auto& insn_ref : instructions)
    {
        auto& insn = insn_ref.get();
        auto offset = insn.Offset();
        Lanes cur;

        cur.forward_lanes[it->LaneNumber()] = it->Calculate(offset);
        m_lanes.push_back(cur);

        if (it->EndsAt(offset))
        {
            auto next = it + 1;
            if (next != m_forward_lanes.end())
            {
                it = next;
            }
        }
    }
}

std::span<const JumpLanes::Lanes>
JumpLanes::GetLanes() const
{
    return m_lanes;
}

unsigned
JumpLanes::Distance(const IInstruction& insn, const IInstruction::Referer& referer) const
{
    return std::abs(static_cast<int32_t>(insn.Offset()) - static_cast<int32_t>(referer.offset));
}
