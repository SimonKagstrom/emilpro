#include <stdio.h>
#include <stdint.h>
#include <opdis/opdis.h>

#include <idisassembly.hh>
#include <utils.hh>

using namespace emilpro;

class Disassembly : public IDisassembly
{
public:
	Disassembly()
	{
	    m_opdis = opdis_init();

	    opdis_set_display(m_opdis, opdisDisplayStatic, (void *)this);
	}

	virtual ~Disassembly()
	{
	    opdis_term(m_opdis);
	}

	bool execute(IDisassembly::IInstructionListener *listener,
			uint8_t *data, size_t size)
	{
		if (!listener)
			return false;

		if (!data || size == 0)
			return false;

		bool out = true;
		opdis_buf_t buf = opdis_buf_alloc(size, 0);

		int v = opdis_buf_fill(buf, 0, data, size);

		if (v == (int)size) {
			m_listener = listener;
			opdis_disasm_linear(m_opdis, buf, 0, size);
		}
		else {
			out = false;
		}

		opdis_buf_free(buf);

		return out;
	}

private:
	void opdisDisplay(const opdis_insn_t *insn)
	{
	    panic_if(!m_listener,
	             "No listener when displaying!");

	    m_listener->onInstruction(insn->offset, insn->ascii);
	}

	static void opdisDisplayStatic(const opdis_insn_t *insn, void *arg)
	{
	    Disassembly *pThis = (Disassembly *)arg;

	    pThis->opdisDisplay(insn);
	}

	opdis_t m_opdis;
	IInstructionListener *m_listener;
};


IDisassembly &IDisassembly::getInstance()
{
	static Disassembly *instance;

	if (!instance)
		instance = new Disassembly();

	return *instance;
}
