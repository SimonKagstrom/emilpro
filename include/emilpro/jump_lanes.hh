#pragma once

#include "i_instruction.hh"

#include <span>
#include <vector>

namespace emilpro
{

class JumpLanes
{
public:
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
        Type backward_lanes[3];
        Type forward_lanes[3];
    };

    void Calculate(unsigned max_distance,
                   std::span<const std::reference_wrapper<IInstruction>> instructions);

    std::span<const Lanes> GetLanes() const;

private:
    std::vector<Lanes> m_lanes;
};

} // namespace emilpro
