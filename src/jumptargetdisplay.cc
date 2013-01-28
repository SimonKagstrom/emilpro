#include <jumptargetdisplay.hh>

#include <list>
#include <unordered_map>
#include <string.h>

using namespace emilpro;

class emilpro::InstructionPair
{
public:
	InstructionPair(IInstruction *start, IInstruction *end, int distance) :
		m_start(start), m_end(end)
	{
		if (distance < 0)
			m_distance = -distance;
		else
			m_distance = distance;
	}

	IInstruction *m_start;
	IInstruction *m_end;
	unsigned m_distance;
};

typedef std::list<InstructionPair *> InstructionPairList_t;
typedef std::unordered_map<uint64_t, InstructionPair *> InstructionPairStartMap_t;
typedef std::unordered_map<uint64_t, std::list<InstructionPair *>> InstructionPairEndMap_t;
typedef std::unordered_map<uint64_t, IInstruction *> InstructionMap_t;


JumpTargetDisplay::JumpTargetDisplay(bool isForward, unsigned nLanes) :
		m_isForward(isForward), m_nLanes(nLanes), m_nRows(1)
{
	m_lanes = new LaneValue_t[m_nLanes * m_nRows];
}

JumpTargetDisplay::~JumpTargetDisplay()
{
	delete[] m_lanes;
}

void JumpTargetDisplay::calculateLanes(InstructionList_t &insns, unsigned nVisibleInsns)
{
	m_nRows = insns.size();
	m_nVisibleInsns = nVisibleInsns;

	// Nothing to do
	if (m_nRows == 0)
		return;

	delete[] m_lanes;

	m_insnNrs.clear();
	m_starts.clear();
	m_ends.clear();
	m_lanes = new LaneValue_t[m_nLanes * m_nRows];

	memset(m_lanes, LANE_INVALID, m_nLanes * m_nRows * sizeof(LaneValue_t));

	InstructionPairList_t pairs;
	InstructionPairStartMap_t pairStartMap;
	InstructionPairEndMap_t pairEndMap;
	InstructionList_t srcs;
	InstructionMap_t insnMap;
	unsigned nr = 0;

	for (InstructionList_t::iterator it = insns.begin();
			it != insns.end();
			++it) {
		IInstruction *cur = *it;

		insnMap[cur->getAddress()] = cur;
		m_insnNrs[cur] = nr;

		if (cur->getType() == IInstruction::IT_CFLOW)
			srcs.push_back(cur);
		nr++;
	}

	// Get all pairs
	for (InstructionList_t::iterator it = srcs.begin();
			it != srcs.end();
			++it) {
		IInstruction *start = *it;
		IInstruction *end = insnMap[start->getBranchTargetAddress()];

		// Jump not in this sequence of instructions???
		if (!end)
			continue;
		m_starts[start->getAddress()] = start;
		m_ends[end->getAddress()] = start;

		InstructionPair *pair = new InstructionPair(start, end, m_insnNrs[end] - m_insnNrs[start]);
		pairs.push_back(pair);
		pairStartMap[start->getAddress()] = pair;
		pairEndMap[end->getAddress()].push_back(pair);
	}

	IInstruction *lanes[m_nLanes];

	memset((void *)lanes, 0, sizeof(IInstruction *) * m_nLanes);

	unsigned row;
	if (!m_isForward) {
		row = insns.size() - 1;

		for (InstructionList_t::reverse_iterator it = insns.rbegin();
				it != insns.rend();
				++it, --row) {
			IInstruction *cur = *it;
			LaneValue_t *curLane = &m_lanes[row * m_nLanes];

			InstructionPair *startPair = pairStartMap[cur->getAddress()];
			std::list<InstructionPair *> endPairs = pairEndMap[cur->getAddress()];

			if (startPair != NULL)
				allocateLane(startPair->m_start, startPair->m_end, lanes);

			fillLane(curLane, cur, lanes);

			for (std::list<InstructionPair *>::iterator itEp = endPairs.begin();
					itEp != endPairs.end();
					++itEp) {
				InstructionPair *p = *itEp;

				deallocateLane(p->m_start, p->m_end, lanes);
			}
		}
	}

	for (InstructionPairList_t::iterator it = pairs.begin();
			it != pairs.end();
			++it) {
		InstructionPair *p = *it;

		delete p;
	}
}

void JumpTargetDisplay::fillLane(LaneValue_t *curRow, IInstruction *cur, IInstruction **lanes)
{
	for (unsigned i = 0; i < m_nLanes; i++) {
		IInstruction *p = lanes[i];

		if (p == NULL) {
			curRow[i] = LANE_NONE;
		} else {
			if (cur == p) // this is a start
				curRow[i] = m_isForward ? LANE_START_DOWN : LANE_START_UP;
			else if (m_ends[cur->getAddress()] != NULL)
				curRow[i] = m_isForward ? LANE_END_DOWN : LANE_END_UP;
			else
				curRow[i] = LANE_LINE;
		}
	}
}

void JumpTargetDisplay::allocateLane(IInstruction *start, IInstruction *end, IInstruction **lanes)
{
	if (!start)
		return;

	if (!end)
		return;

	int distance = m_insnNrs[end] - m_insnNrs[start];

	if (distance < 0)
		distance = -distance;

	// Too large
	if (distance > (int)m_nVisibleInsns)
		return;

	unsigned i;

	for (i = 0; i < m_nLanes; i++) {
		IInstruction *cur = lanes[i];

		if (!cur)
			break;
	}
	// Can't fit this one, so skip it
	if (i == m_nLanes)
		return;

	lanes[i] = start;
}

void JumpTargetDisplay::deallocateLane(IInstruction *start, IInstruction *end, IInstruction **lanes)
{
	if (!start)
		return;

	if (!end)
		return;

	unsigned i;

	for (i = 0; i < m_nLanes; i++) {
		if (lanes[i] == start)
			break;
	}

	if (i == m_nLanes)
		return;

	lanes[i] = NULL;
}

bool JumpTargetDisplay::getLanes(unsigned insnNr, JumpTargetDisplay::LaneValue_t *lanesOut)
{
	if (insnNr > m_nRows)
		return false;

	memcpy(lanesOut, &m_lanes[insnNr * m_nLanes], m_nLanes * sizeof(LaneValue_t));

	return true;
}
