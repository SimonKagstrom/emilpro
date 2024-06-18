#include "emilpro/jump_lanes.hh"

#include <etl/vector.h>
#include <fmt/format.h>

using namespace emilpro;


void
JumpLanes::Calculate(unsigned max_distance,
                     std::span<const std::reference_wrapper<IInstruction>> instructions)
{
    m_lanes.clear();
    std::vector<std::reference_wrapper<IInstruction>> refering_instructions;

    std::vector<Lane> long_jumps;

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

        if (refers_to != std::nullopt && insn.Type() == IInstruction::InstructionType::kBranch)
        {
            if (Distance(insn, *refers_to) > max_distance)
            {
                long_jumps.emplace_back(insn.Offset(), refers_to->offset, max_distance);
            }
            else
            {
                refering_instructions.push_back(insn_ref);
            }
        }
    }

    std::vector<Lane> forward_lanes;
    std::vector<Lane> backward_lanes;

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

    if (forward_lanes.empty() && backward_lanes.empty() && long_jumps.empty())
    {
        m_lanes.resize(instructions.size());
        return;
    }


    etl::vector<const Lane*, JumpLanes::kNumberOfLanes> current_lanes_forward;
    etl::vector<const Lane*, JumpLanes::kNumberOfLanes> current_lanes_backward;

    for (auto& insn_ref : instructions)
    {
        auto fwd = Process(insn_ref.get(), forward_lanes, current_lanes_forward);
        auto rev = Process(insn_ref.get(), backward_lanes, current_lanes_backward);

        m_lanes.emplace_back(rev, fwd);
    }

    for (auto& lane : long_jumps)
    {
        if (lane.StartsAt() >= m_lanes.size())
        {
            continue;
        }
        if (lane.IsForward())
        {
            m_lanes[lane.StartsAt()].forward_lanes[0] = JumpLanes::Type::kLongStart;
            if (lane.EndsAt() < m_lanes.size())
            {
                m_lanes[lane.EndsAt()].forward_lanes[0] = JumpLanes::Type::kLongEnd;
            }
        }
        else
        {
            m_lanes[lane.StartsAt()].backward_lanes[0] = JumpLanes::Type::kLongStart;
            if (lane.EndsAt() < m_lanes.size())
            {
                m_lanes[lane.EndsAt()].backward_lanes[0] = JumpLanes::Type::kLongEnd;
            }
        }
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

    const auto& lane = lanes.back();
    for (auto it = lanes.rbegin() + 1; it != lanes.rend(); ++it)
    {
        auto& last = *it;

        if (last.Encloses(lane) || last.Overlaps(lane))
        {
            last.PushOut();
        }
    }
}

std::array<JumpLanes::Type, JumpLanes::kNumberOfLanes>
JumpLanes::Process(const IInstruction& insn,
                   std::vector<Lane>& lanes,
                   etl::vector<const Lane*, JumpLanes::kNumberOfLanes>& current_lanes) const
{
    std::array<Type, kNumberOfLanes> cur {};
    etl::vector<const Lane*, JumpLanes::kNumberOfLanes> to_erase;
    auto offset = insn.Offset();

    for (auto& lane : lanes)
    {
        if (lane.Covers(offset) &&
            std::ranges::find(current_lanes, std::to_address(&lane)) == current_lanes.end())
        {
            if (!current_lanes.full())
                current_lanes.push_back(std::to_address(&lane));
        }
    }

    for (auto lane : current_lanes)
    {
        if (!lane->Covers(offset))
        {
            to_erase.push_back(lane);
        }
        else if (lane->LaneNumber() < kNumberOfLanes)
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


JumpLanes::Type
JumpLanes::Lane::Calculate(uint64_t offset) const
{
    auto is_long = Distance() > m_max_distance;

    if (offset == m_first)
    {
        if (IsForward())
        {
            return is_long ? Type::kLongStart : Type::kStart;
        }
        return is_long ? Type::kLongEnd : Type::kEnd;
    }
    else if (offset == m_last)
    {
        if (IsForward())
        {
            return is_long ? Type::kLongEnd : Type::kEnd;
        }

        return is_long ? Type::kLongStart : Type::kStart;
    }
    else if (offset > m_first && offset < m_last && !is_long)
    {
        return Type::kTraffic;
    }

    return Type::kNone;
}
