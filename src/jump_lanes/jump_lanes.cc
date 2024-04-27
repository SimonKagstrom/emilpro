#include "emilpro/jump_lanes.hh"

#include <etl/vector.h>
#include <fmt/format.h>

using namespace emilpro;

namespace
{

}


void
JumpLanes::Calculate(unsigned max_distance,
                     std::span<const std::reference_wrapper<IInstruction>> instructions)
{
    m_lanes.clear();
    std::vector<std::reference_wrapper<IInstruction>> refering_instructions;
    std::vector<Lane> forward_lanes;
    std::vector<Lane> backward_lanes;

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

        if (insn.RefersTo())
        {
            refering_instructions.push_back(insn_ref);
        }
    }

    for (const auto& insn_ref : refering_instructions)
    {
        const auto& insn = insn_ref.get();
        auto refers_to = insn.RefersTo();

        if (insn.Offset() < refers_to->offset)
        {
            forward_lanes.emplace_back(insn.Offset(), refers_to->offset, max_distance);
            PushPredecessors(forward_lanes);
        }
    }

    // std::ranges::reverse_view, but not on clang/MacOS
    for (auto i = refering_instructions.size(); i > 0; i--)
    {
        const auto& insn_ref = refering_instructions[i - 1];
        const auto& insn = insn_ref.get();
        auto refers_to = insn.RefersTo();

        if (insn.Offset() > refers_to->offset)
        {
            backward_lanes.emplace_back(insn.Offset(), refers_to->offset, max_distance);
            PushPredecessors(backward_lanes);
        }
    }

    if (forward_lanes.empty() && backward_lanes.empty())
    {
        m_lanes.resize(instructions.size());
        return;
    }

    etl::vector<const Lane*, JumpLanes::kNumberOfLanes> current_lanes_forward;
    etl::vector<const Lane*, JumpLanes::kNumberOfLanes> current_lanes_backward;
    auto it_forward = forward_lanes.begin();
    auto it_backward = backward_lanes.begin();
    for (auto& insn_ref : instructions)
    {
        auto fwd = Process(insn_ref.get(), forward_lanes, it_forward, current_lanes_forward);
        auto rev = Process(insn_ref.get(), backward_lanes, it_backward, current_lanes_backward);

        m_lanes.emplace_back(rev, fwd);
    }
}

void
JumpLanes::PushPredecessors(std::vector<Lane>& lanes) const
{
    if (lanes.size() < 2)
    {
        // Nothing to push in this case
        return;
    }

    auto lane = lanes.back();
    auto& last = lanes[lanes.size() - 2];

    if (lane.Encloses(last))
    {
        lane.PushOut();
    }
    else if (last.Encloses(lane))
    {
        last.PushOut();
    }
}

std::array<JumpLanes::Type, JumpLanes::kNumberOfLanes>
JumpLanes::Process(const IInstruction& insn,
                   std::vector<Lane>& lanes,
                   std::vector<Lane>::iterator& it,
                   etl::vector<const Lane*, JumpLanes::kNumberOfLanes>& current_lanes) const
{
    std::array<Type, kNumberOfLanes> cur {};
    etl::vector<const Lane*, JumpLanes::kNumberOfLanes> to_erase;
    auto offset = insn.Offset();

    if (it != lanes.end() && it->Covers(offset))
    {
        if (!current_lanes.full())
        {
            current_lanes.push_back(std::to_address(it));
        }
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
            cur[lane->LaneNumber()] = lane->Calculate(offset);
        }
    }
    for (auto lane : to_erase)
    {
        current_lanes.erase(std::remove(current_lanes.begin(), current_lanes.end(), lane),
                            current_lanes.end());
    }

    return cur;
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
