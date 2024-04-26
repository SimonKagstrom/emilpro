#pragma once

#include "i_instruction.hh"

#include <cmath>
#include <cstdlib>
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
        Lanes()
        {
            std::fill(backward_lanes.begin(), backward_lanes.end(), Type::kNone);
            std::fill(forward_lanes.begin(), forward_lanes.end(), Type::kNone);
        }

        std::array<Type, kNumberOfLanes> backward_lanes;
        std::array<Type, kNumberOfLanes> forward_lanes;
    };

    void Calculate(unsigned max_distance,
                   std::span<const std::reference_wrapper<IInstruction>> instructions);

    std::span<const Lanes> GetLanes() const;

private:
    class Lane
    {
    public:
        Lane(uint32_t start, uint32_t end)
            : m_start(start)
            , m_end(end)
        {
        }

        bool Covers(uint32_t offset) const
        {
            return offset >= m_start && offset <= m_end;
        }

        bool EndsAt(uint32_t offset) const
        {
            return offset >= m_end;
        }

        unsigned LaneNumber() const
        {
            return m_lane;
        }

        void PushOut()
        {
            m_lane++;
        }

        bool IsForward() const
        {
            return m_start <= m_end;
        }

        bool Overlaps(const Lane& other) const
        {
            return m_start < other.m_start && m_end <= other.m_end;
        }

        bool Encloses(const Lane& other) const
        {
            return m_start < other.m_start && m_end >= other.m_end;
        }

        Type Calculate(uint32_t offset) const
        {
            if (offset == m_start)
            {
                return Type::kStart;
            }
            else if (offset == m_end)
            {
                return Type::kEnd;
            }
            else if (offset > m_start && offset < m_end)
            {
                return Type::kTraffic;
            }

            return Type::kNone;
        }

    private:
        const uint32_t m_start;
        const uint32_t m_end;
        unsigned m_lane {0}; // The inner lane
    };

    unsigned Distance(const IInstruction& insn, const IInstruction::Referer& referer) const;

    std::vector<Lanes> m_lanes;
    std::vector<Lane> m_forward_lanes;

    std::vector<std::reference_wrapper<Lane>> m_lane_stack;
};

} // namespace emilpro
