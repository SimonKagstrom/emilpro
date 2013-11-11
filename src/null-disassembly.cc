#include <idisassembly.hh>

using namespace emilpro;

static IDisassembly *g_instance;

class NullDisassembly : public IDisassembly
{
public:
	NullDisassembly()
	{
	}

	virtual InstructionList_t execute(void *data, size_t size, uint64_t address)
	{
		InstructionList_t out;

		return out;
	}

	virtual void destroy()
	{
		g_instance = NULL;

		delete this;
	}
};


IDisassembly &IDisassembly::instance()
{
	if (!g_instance) {
		g_instance = new NullDisassembly();
	}

	return *g_instance;
}
