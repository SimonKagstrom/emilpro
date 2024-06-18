#pragma once

#include "i_instruction.hh"

#include <cassert>
#include <cmath>
#include <cstdlib>
#include <etl/vector.h>
#include <fmt/format.h>
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
        Lane(uint64_t start, uint64_t end, uint32_t max_distance)
            : m_forward(start <= end)
            , m_first(m_forward ? start : end)
            , m_last(m_forward ? end : start)
            , m_max_distance(max_distance)
        {
            assert(m_last >= m_first);
        }

        bool Covers(uint64_t offset) const
        {
            return offset >= m_first && offset <= m_last;
        }

        uint64_t StartsAt() const
        {
            return m_first;
        }

        uint64_t EndsAt() const
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
            // Either of the two lanes cross the other
            return m_first < other.m_first && m_last > other.m_first ||
                   m_first < other.m_last && m_last > other.m_last;
        }

        bool Encloses(const Lane& other) const
        {
            return m_first < other.m_first && m_last >= other.m_last;
        }

        Type Calculate(uint64_t offset) const;

    private:
        uint64_t Distance() const
        {
            return m_last - m_first;
        }

        const bool m_forward;
        const uint64_t m_first;
        const uint64_t m_last;
        const uint32_t m_max_distance;

        unsigned m_lane {0}; // The inner lane
    };

    unsigned Distance(const IInstruction& insn, const IInstruction::Referer& referer) const;

    void PushPredecessors(std::vector<Lane>& lanes) const;

    std::array<Type, kNumberOfLanes>
    Process(const IInstruction& insn,
            std::vector<Lane>& lanes,
            etl::vector<const Lane*, JumpLanes::kNumberOfLanes>& current_lanes) const;

    std::vector<Lanes> m_lanes;
};

} // namespace emilpro
