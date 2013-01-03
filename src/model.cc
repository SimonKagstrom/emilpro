#include <model.hh>
#include <symbolfactory.hh>
#include <isymbolprovider.hh>
#include <idisassembly.hh>

#include <unordered_map>

using namespace emilpro;

class BasicBlock : public Model::IBasicBlock
{
public:
	virtual ~BasicBlock()
	{
	}

	bool hasInstructions()
	{
		return m_instructions.size() != 0;
	}

	void addInstruction(IInstruction *which)
	{
		m_instructions.push_back(which);
	}

	InstructionList_t getInstructions()
	{
		return m_instructions;
	}

private:
	InstructionList_t m_instructions;
};



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

Model::BasicBlockList_t Model::getBasicBlocksFromInstructions(const InstructionList_t &instructions)
{
	typedef std::unordered_map<uint64_t, IInstruction *> BranchMap_t;

	Model::BasicBlockList_t out;
	BranchMap_t targets;

	for (InstructionList_t::const_iterator it = instructions.begin();
			it != instructions.end();
			++it) {
		IInstruction *cur = *it;

		if (cur->getType() != IInstruction::IT_CFLOW)
			continue;

		targets[cur->getAddress()] = cur;
		targets[cur->getBranchTargetAddress()] = cur;
	}

	BasicBlock *p = new BasicBlock();
	for (InstructionList_t::const_iterator it = instructions.begin();
			it != instructions.end();
			++it) {
		IInstruction *cur = *it;

		p->addInstruction(cur);

		if (targets[cur->getAddress()] && p->hasInstructions()) {
			out.push_back(p);

			p = new BasicBlock();
		}
	}

	if (out.back() != p)
		out.push_back(p);

	return out;
}


void Model::onSymbol(ISymbol &sym)
{
	ISymbol::SymbolType type = sym.getType();

	if (type == ISymbol::SYM_DATA || type == ISymbol::SYM_TEXT)
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

