#pragma once

#include "i_instruction.hh"

#include <cassert>
#include <cmath>
#include <cstdlib>
#include <etl/vector.h>
#include <span>
#include <vector>

namespace emilpro
{

class JumpLanes
{
public:
    constexpr static auto kNumberOfLanes = 4;

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
        kStartEnd,  // Jump here + start from here
        kLongStart, // Start without lanes
        kLongEnd,
    };

    struct Lanes
    {
        Lanes()
        {
            std::ranges::fill(backward_lanes, Type::kNone);
            std::ranges::fill(forward_lanes, Type::kNone);
        }

        Lanes(auto backward, auto forward)
            : backward_lanes(backward)
            , forward_lanes(forward)
        {
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
        Lane(uint32_t start, uint32_t end, uint32_t max_distance)
            : m_forward(start <= end)
            , m_first(m_forward ? start : end)
            , m_last(m_forward ? end : start)
            , m_max_distance(max_distance)
        {
            assert(m_last >= m_first);
        }

        bool Covers(uint32_t offset) const
        {
            return offset >= m_first && offset <= m_last;
        }

        uint32_t StartsAt() const
        {
            return m_first;
        }

        uint32_t EndsAt() const
        {
            return m_last;
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
            return m_forward;
        }

        bool Overlaps(const Lane& other) const
        {
            return m_first < other.m_first && m_last <= other.m_last;
        }

        bool Encloses(const Lane& other) const
        {
            return m_first < other.m_first && m_last >= other.m_last;
        }

        Type Calculate(uint32_t offset) const
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

    private:
        uint32_t Distance() const
        {
            return m_last - m_first;
        }

        const bool m_forward;
        const uint32_t m_first;
        const uint32_t m_last;
        const uint32_t m_max_distance;

        unsigned m_lane {0}; // The inner lane
    };

    unsigned Distance(const IInstruction& insn, const IInstruction::Referer& referer) const;

    void PushPredecessors(std::vector<Lane>& lanes) const;

    std::array<Type, kNumberOfLanes>
    Process(const IInstruction& insn,
            std::vector<Lane>& lanes,
            std::vector<Lane>::iterator& it,
            etl::vector<const Lane*, JumpLanes::kNumberOfLanes>& current_lanes) const;

    std::vector<Lanes> m_lanes;
};

} // namespace emilpro
