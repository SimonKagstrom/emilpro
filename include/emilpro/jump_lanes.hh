#pragma once

#include "i_instruction.hh"

#include <span>
#include <vector>

namespace emilpro
{

class JumpLanes
{
public:
    constexpr static auto kNumberOfLanes = 3;

    enum class LaneState
    {
        kNone,
        kStart,
        kTraffic,
        kEnd,
    };

    enum class Type
    {
        kNone,
        kStart,
        kTraffic,
        kEnd,
        kStartEnd, // Jump here + start from here
    };

    struct Lanes
    {
        Type backward_lanes[kNumberOfLanes] {Type::kNone, Type::kNone, Type::kNone};
        Type forward_lanes[kNumberOfLanes] {Type::kNone, Type::kNone, Type::kNone};
    };

    void Calculate(unsigned max_distance,
                   std::span<const std::reference_wrapper<IInstruction>> instructions);

    std::span<const Lanes> GetLanes() const;

private:
    LaneState m_state[kNumberOfLanes] {LaneState::kNone, LaneState::kNone, LaneState::kNone};
    std::vector<Lanes> m_lanes;
};

} // namespace emilpro
