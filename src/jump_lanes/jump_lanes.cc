#include "emilpro/jump_lanes.hh"

#include <etl/vector.h>

using namespace emilpro;


void
JumpLanes::Calculate(unsigned max_distance,
                     std::span<const std::reference_wrapper<IInstruction>> instructions)
{
    m_lanes.clear();

    /*
     * Rules:
     *
     * - Max 3 lanes
     * - Longer enclsoing branches are pushed out (shorter on the closest lanes)
     * - Crossing branches are pushed out
     */
    for (auto& insn_ref : instructions)
    {
        const auto& insn = insn_ref.get();
        auto refers_to = insn.RefersTo();

        if (refers_to && Distance(insn, *refers_to) <= max_distance)
        {
            if (insn.Offset() < refers_to->offset)
            {
                m_forward_lanes.emplace_back(insn.Offset(), refers_to->offset);
                auto lane = m_forward_lanes.back();
                auto last = m_forward_lanes.size() > 1
                                ? &m_forward_lanes[m_forward_lanes.size() - 2]
                                : nullptr;

                if (last)
                {
                    if (lane.Encloses(*last))
                    {
                        lane.PushOut();
                    }
                    else if (last->Encloses(lane))
                    {
                        last->PushOut();
                    }
                }
            }
        }
    }

    if (m_forward_lanes.empty())
    {
        m_lanes.resize(instructions.size());
        return;
    }

    etl::vector<const Lane*, JumpLanes::kNumberOfLanes> current_lanes;
    auto it = m_forward_lanes.begin();
    for (auto& insn_ref : instructions)
    {
        etl::vector<const Lane*, JumpLanes::kNumberOfLanes> to_erase;
        const auto& insn = insn_ref.get();
        auto offset = insn.Offset();
        Lanes cur;

        if (it != m_forward_lanes.end() && it->Covers(offset))
        {
            current_lanes.push_back(&(*it));
            ++it;
        }

        for (auto lane : current_lanes)
        {
            if (!lane->Covers(offset))
            {
                to_erase.push_back(lane);
            }
            else
            {
                cur.forward_lanes[lane->LaneNumber()] = lane->Calculate(offset);
            }
        }
        for (auto lane : to_erase)
        {
            current_lanes.erase(std::remove(current_lanes.begin(), current_lanes.end(), lane),
                                current_lanes.end());
        }

        m_lanes.push_back(cur);
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
