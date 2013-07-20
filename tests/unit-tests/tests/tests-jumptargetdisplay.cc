#include "../test.hh"

#include <utils.hh>
#include <jumptargetdisplay.hh>

using namespace emilpro;

class MockInstruction : public IInstruction
{
public:
	MockInstruction(uint64_t address, InstructionType_t type, uint64_t branchTarget) :
		m_address(address), m_branchTarget(branchTarget), m_type(type)
	{
	}

	virtual ~MockInstruction()
	{
	}

	uint64_t getAddress()
	{
		return m_address;
	}

	InstructionType_t getType()
	{
		return m_type;
	}

	MOCK_METHOD0(getSize, uint64_t());

	/**
	 * Return the target address for branches/calls.
	 */
	uint64_t getBranchTargetAddress()
	{
		return m_branchTarget;
	}

	MOCK_METHOD0(isPrivileged, Ternary_t());

	MOCK_METHOD0(getString, std::string &());

	MOCK_METHOD0(getMnemonic, std::string &());

	const OperandList_t &getOperands()
	{
		return m_operands;
	}

	MOCK_METHOD1(getRawData, uint8_t *(size_t &sz));

	uint64_t m_address;
	uint64_t m_branchTarget;
	InstructionType_t m_type;
	OperandList_t m_operands;
};

class JumpTargetFixture
{
public:
	JumpTargetFixture() :
		m_address(4)
	{
	}

	~JumpTargetFixture()
	{
		cleanup();
	}

	void cleanup()
	{
		for (InstructionList_t::iterator it = m_insns.begin();
				it != m_insns.end();
				++it) {
			IInstruction *cur = *it;

			delete cur;
		}

		m_insns.clear();
	}

	uint64_t addInstruction(uint64_t branchTarget = 0)
	{
		uint64_t out = m_address;

		IInstruction::InstructionType_t type = branchTarget != 0 ? IInstruction::IT_CFLOW : IInstruction::IT_ARITHMETIC_LOGIC;
		MockInstruction *insn = new MockInstruction(m_address, type, branchTarget);

		m_insns.push_back(insn);

		m_address += 4;

		return out;
	}

	bool laneHasValue(JumpTargetDisplay *p, unsigned idx, unsigned nLanes, JumpTargetDisplay::LaneValue_t value, bool onlyValue = false)
	{
		JumpTargetDisplay::LaneValue_t lanes[nLanes];

		p->getLanes(idx, lanes);

		if (onlyValue) {
			for (unsigned i = 0; i < nLanes; i++) {
				if (lanes[i] != value)
					return false;
			}

			return true;
		}

		for (unsigned i = 0; i < nLanes; i++) {
			if (lanes[i] == value)
				return true;
		}

		return false;
	}


	void print(JumpTargetDisplay *p, unsigned nLanes)
	{
		printf("\n");

		unsigned i = 0;
		for (InstructionList_t::iterator it = m_insns.begin();
				it != m_insns.end();
				++it, ++i) {
			printf("%3d:  ", i);

			MockInstruction *cur = (MockInstruction *)*it;
			JumpTargetDisplay::LaneValue_t lanes[nLanes];

			p->getLanes(i, lanes);

			for (unsigned j = 0; j < nLanes; j++) {
				switch (lanes[j]) {
				case JumpTargetDisplay::LANE_NONE:
					printf("   "); break;
				case JumpTargetDisplay::LANE_LINE:
					printf(" | "); break;
				case JumpTargetDisplay::LANE_START_DOWN:
					printf(" v "); break;
				case JumpTargetDisplay::LANE_START_UP:
					printf(" ^ "); break;
				case JumpTargetDisplay::LANE_END_DOWN:
					printf(" v>"); break;
				case JumpTargetDisplay::LANE_END_UP:
					printf(" ^>"); break;
				case JumpTargetDisplay::LANE_START_LONG_DOWN:
					printf(" lv"); break;
				case JumpTargetDisplay::LANE_START_LONG_UP:
					printf(" l^"); break;
				case JumpTargetDisplay::LANE_END_LONG_DOWN:
					printf("ld>"); break;
				case JumpTargetDisplay::LANE_END_LONG_UP:
					printf("lu>"); break;
				default:
					printf("XXX"); break;
					break;
				}
				printf(".");
			}

			printf("  INSN %s\n", cur->m_branchTarget == 0 ? "" : "source");
		}
	}

	InstructionList_t m_insns;
	uint64_t m_address;
};

TESTSUITE(jumptarget)
{
	TEST(backwards, JumpTargetFixture)
	{
		ASSERT_SCOPE_HEAP_LEAK_FREE
		{
			JumpTargetDisplay *p = new JumpTargetDisplay(false, 4);

			addInstruction(8); // Branch forward
			uint64_t first = addInstruction();
			uint64_t second = addInstruction();
			addInstruction(first);
			addInstruction(second);
			addInstruction();

			p->calculateLanes(m_insns, 10);
			p->calculateLanes(m_insns, 10);

			print(p, 4);

			ASSERT_TRUE(laneHasValue(p, 3, 4, JumpTargetDisplay::LANE_START_UP));
			ASSERT_TRUE(laneHasValue(p, 1, 4, JumpTargetDisplay::LANE_END_UP));
			ASSERT_TRUE(laneHasValue(p, 5, 4, JumpTargetDisplay::LANE_NONE, true));
			ASSERT_TRUE(laneHasValue(p, 2, 4, JumpTargetDisplay::LANE_END_UP));
			ASSERT_TRUE(laneHasValue(p, 2, 4, JumpTargetDisplay::LANE_LINE));
			ASSERT_TRUE(laneHasValue(p, 0, 4, JumpTargetDisplay::LANE_NONE, true));

			cleanup();
			delete p;
		}
	}


	TEST(forwards, JumpTargetFixture)
	{
		ASSERT_SCOPE_HEAP_LEAK_FREE
		{
			unsigned nLanes = 6;
			JumpTargetDisplay *p = new JumpTargetDisplay(true, nLanes);

			addInstruction(); // 4
			addInstruction(28);
			addInstruction(24);
			addInstruction(4); // Jump back, should be ignored
			addInstruction();
			addInstruction(); // 24
			addInstruction(); // 28

			p->calculateLanes(m_insns, 4);

			print(p, nLanes);

			ASSERT_TRUE(laneHasValue(p, 0, nLanes, JumpTargetDisplay::LANE_NONE, true));
			ASSERT_TRUE(laneHasValue(p, 1, nLanes, JumpTargetDisplay::LANE_START_LONG_DOWN));
			ASSERT_TRUE(laneHasValue(p, 2, nLanes, JumpTargetDisplay::LANE_START_DOWN));
			ASSERT_TRUE(laneHasValue(p, 3, nLanes, JumpTargetDisplay::LANE_LINE));
			ASSERT_FALSE(laneHasValue(p, 3, nLanes, JumpTargetDisplay::LANE_START_UP));
			ASSERT_TRUE(laneHasValue(p, 5, nLanes, JumpTargetDisplay::LANE_END_DOWN));
			ASSERT_TRUE(laneHasValue(p, 6, nLanes, JumpTargetDisplay::LANE_END_LONG_DOWN));

			cleanup();
			delete p;
		}
	}


	TEST(fillLanes, JumpTargetFixture)
	{
			unsigned nLanes = 4;
			JumpTargetDisplay *p = new JumpTargetDisplay(false, nLanes);

			uint64_t a = addInstruction();
			uint64_t b = addInstruction();
			uint64_t c = addInstruction();
			uint64_t d = addInstruction();
			addInstruction(a);
			addInstruction(b);
			addInstruction(c);
			addInstruction(d); // Should be ignored

			p->calculateLanes(m_insns, 10);
			p->calculateLanes(m_insns, 10);

			print(p, nLanes);
			ASSERT_FALSE(laneHasValue(p, 4, nLanes, JumpTargetDisplay::LANE_START_UP));
			ASSERT_TRUE(laneHasValue(p, 7, nLanes, JumpTargetDisplay::LANE_START_UP));

			cleanup();
			delete p;
	}
}
