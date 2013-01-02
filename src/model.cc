#include <model.hh>
#include <symbolfactory.hh>
#include <isymbolprovider.hh>
#include <idisassembly.hh>

using namespace emilpro;

Model::Model() :
		m_memory(NULL)
{
	SymbolFactory::instance().registerListener(this);
}

Model::~Model()
{
}

bool Model::addData(void *data, size_t size)
{
	SymbolFactory &factory = SymbolFactory::instance();
	unsigned res;

	res = factory.parseBestProvider(data, size);

	// Should really never happen
	if (res == ISymbolProvider::NO_MATCH)
		return false;

	return true;
}

const InstructionList_t Model::getInstructions(uint64_t start, uint64_t end)
{
	InstructionList_t out;
	uint64_t curAddress = start;

	// Instructions here?
	while (1) {
		if (curAddress >= end)
			break;

		if (!m_instructionCache[curAddress]) {
			SymbolAddressMap_t::iterator it = m_symbolsByAddress.lower_bound(curAddress);

			if (it == m_symbolsByAddress.end())
				break;

			fillCacheWithSymbol(it->second);
		}

		IInstruction *p = m_instructionCache[curAddress];
		if (!p)
			break;

		if (p->getSize() == 0)
			break;

		out.push_back(p);

		curAddress = p->getAddress() + p->getSize();
	}

	return out;
}

void Model::fillCacheWithSymbol(ISymbol *sym)
{
	InstructionList_t lst = IDisassembly::instance().execute(sym->getDataPtr(), sym->getSize(), sym->getAddress());

	for (InstructionList_t::iterator it = lst.begin();
			it != lst.end();
			++it) {
		IInstruction *cur = *it;

		m_instructionCache[cur->getAddress()] = cur;
	}
}

void Model::onSymbol(ISymbol &sym)
{
	m_symbolsByAddress[sym.getAddress()] = &sym;
}


static Model *g_instance;
void Model::destroy()
{
	g_instance = NULL;

	delete this;
}

Model &Model::instance()
{
	if (!g_instance)
		g_instance = new Model();

	return *g_instance;
}

