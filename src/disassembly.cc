#include <stdio.h>
#include <stdint.h>
#include <opdis/opdis.h>

#include <idisassembly.hh>
#include <iinstruction.hh>
#include <utils.hh>

using namespace emilpro;

class Operand : public IOperand
{
public:
	Operand(const char *encoding) :
		m_encoding(encoding)
	{
	}

	virtual std::string &getEncoding()
	{
		return m_encoding;
	}

private:
	std::string m_encoding;
};

class Instruction : public IInstruction
{
public:
	Instruction(uint64_t address, InstructionType_t type, const char *encoding, Ternary_t privileged) :
		m_address(address),
		m_type(type),
		m_encoding(encoding),
		m_privileged(privileged)
	{
	}

	virtual ~Instruction()
	{
		for (OperandList_t::iterator it = m_operands.begin();
				it != m_operands.end();
				it++)
			delete *it;
	}

	uint64_t getAddress()
	{
		return m_address;
	}

	Ternary_t isPrivileged()
	{
		return m_privileged;
	}

	InstructionType_t getType()
	{
		return m_type;
	}

	std::string &getEncoding()
	{
		return m_encoding;
	}

	const OperandList_t &getOperands()
	{
		return m_operands;
	}

private:
	uint64_t m_address;
	InstructionType_t m_type;
	std::string m_encoding;
	Ternary_t m_privileged;

	IInstruction::OperandList_t m_operands;
};

class Disassembly : public IDisassembly
{
public:
	Disassembly()
	{
	    m_opdis = opdis_init();
	    m_list = NULL;
	    m_startAddress = 0;

	    opdis_set_display(m_opdis, opdisDisplayStatic, (void *)this);
	}

	virtual ~Disassembly()
	{
	    opdis_term(m_opdis);
	}

	InstructionList_t execute(void *p, size_t size, uint64_t address)
	{
		InstructionList_t out;
		uint8_t *data = (uint8_t *)p;

		if (!data || size == 0)
			return out;

		opdis_buf_t buf = opdis_buf_alloc(size, 0);

		int v = opdis_buf_fill(buf, 0, data, size);

		if (v == (int)size) {
			m_list = &out;
			m_startAddress = address;
			opdis_disasm_linear(m_opdis, buf, 0, size);
		}

		opdis_buf_free(buf);
		m_list = NULL;
		m_startAddress = 0;

		return out;
	}

private:
	void opdisDisplay(const opdis_insn_t *insn)
	{
		panic_if(!m_list,
				"No list when displaying!");

		uint64_t address = m_startAddress + insn->offset;
		IInstruction::InstructionType_t type = IInstruction::IT_UNKNOWN;
		const char *encoding = insn->ascii;
		IInstruction::Ternary_t privileged = IInstruction::T_unknown;

		if (insn->status & opdis_decode_mnem_flags) {
			privileged = IInstruction::T_false;

			switch (insn->category)
			{
			case opdis_insn_cat_cflow:
				type = IInstruction::IT_CFLOW;
				break;
			case opdis_insn_cat_lost:
			case opdis_insn_cat_stack:
				type = IInstruction::IT_DATA_HANDLING;
				break;
			case opdis_insn_cat_test:
			case opdis_insn_cat_math:
			case opdis_insn_cat_bit:
				type = IInstruction::IT_ARITHMETIC_LOGIC;
				break;
			case opdis_insn_cat_priv:
				type = IInstruction::IT_OTHER;
				privileged = IInstruction::T_true;
				break;
			default:
				type = IInstruction::IT_OTHER;
				break;
			}
		}

		Instruction *cur = new Instruction(address, type, encoding, privileged);

		m_list->push_back(cur);
	}

	static void opdisDisplayStatic(const opdis_insn_t *insn, void *arg)
	{
	    Disassembly *pThis = (Disassembly *)arg;

	    pThis->opdisDisplay(insn);
	}

	opdis_t m_opdis;
	InstructionList_t *m_list;
	uint64_t m_startAddress;
};


IDisassembly &IDisassembly::getInstance()
{
	static Disassembly *instance;

	if (!instance)
		instance = new Disassembly();

	return *instance;
}
