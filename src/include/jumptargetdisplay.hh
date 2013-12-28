#pragma once

#include "iinstruction.hh"

#include <unordered_map>
#include <list>

namespace emilpro
{
	class InstructionPair;

	typedef std::list<InstructionPair *> InstructionPairList_t;
	typedef std::unordered_map<uint64_t, InstructionPair *> InstructionPairStartMap_t;
	typedef std::unordered_map<uint64_t, std::list<InstructionPair *>> InstructionPairEndMap_t;

	class JumpTargetDisplay
	{
	public:
		typedef enum
		{
			LANE_NONE            = 0,
			LANE_LINE            = 1,
			LANE_START_DOWN      = 2,
			LANE_START_UP        = 3,
			LANE_START_LONG_UP   = 4,
			LANE_START_LONG_DOWN = 5,
			LANE_END_DOWN        = 6,
			LANE_END_UP          = 7,
			LANE_END_LONG_DOWN   = 8,
			LANE_END_LONG_UP     = 9,

			LANE_INVALID         = 10,

			LANE_N_VALUES,
		} LaneValue_t;

		JumpTargetDisplay(bool isForward, unsigned n_lanes);

		~JumpTargetDisplay();

		void calculateLanes(const InstructionList_t &insns, unsigned nVisibleInsns);

		bool getLanes(unsigned insnNr, LaneValue_t *lanesOut);

	private:
		typedef std::unordered_map<IInstruction *, unsigned> InstructionNrMap_t;

		void allocateLane(IInstruction *start, IInstruction *end, IInstruction **lanes);
		void deallocateLane(IInstruction *start, IInstruction *end, IInstruction **lanes);

		void fillLane(LaneValue_t *curRow, IInstruction *cur, IInstruction **lanes);

		bool m_isForward;
		unsigned m_nLanes;
		unsigned m_nRows;
		LaneValue_t *m_lanes;

		InstructionNrMap_t m_insnNrs;
		InstructionPairStartMap_t m_starts;
		InstructionPairEndMap_t m_ends;

		unsigned m_nVisibleInsns;
	};
}
