#include <stdio.h>
#include <stdint.h>
#include <opdis/opdis.h>

#include <idisassembly.hh>
#include <iinstruction.hh>
#include <utils.hh>

using namespace emilpro;

class Instruction : public IInstruction
{
public:
	Instruction(uint64_t address) :
		m_address(address)
	{
	}

	uint64_t getAddress()
	{
		return m_address;
	}

private:
	uint64_t m_address;
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

	    Instruction *cur = new Instruction(m_startAddress + insn->offset);

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
