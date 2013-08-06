#include <model.hh>
#include <symbolfactory.hh>
#include <isymbolprovider.hh>
#include <idisassembly.hh>
#include <utils.hh>

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
	unsigned cores = get_number_of_cores();

	m_threads = new std::thread*[cores];
	m_workQueues = new SymbolQueue_t[cores];

	for (unsigned i = 0; i < cores; i++)
		m_threads[i] = NULL;

	SymbolFactory::instance().registerListener(this);
}

Model::~Model()
{
	unsigned cores = get_number_of_cores();

	for (unsigned i = 0; i < cores; i++) {
		if (m_threads[i])
			m_threads[i]->join();
	}

	delete[] m_threads;
	delete[] m_workQueues;

	for (InstructionMap_t::iterator it = m_instructionCache.begin();
			it != m_instructionCache.end();
			++it) {
		IInstruction *p = it->second;

		delete p;
	}
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
	m_mutex.lock();
	while (1) {
		if (curAddress >= end)
			break;

		if (!m_instructionCache[curAddress]) {

			const Model::SymbolList_t syms = getNearestSymbolLocked(curAddress);

			if (syms.empty())
				break;

			if (syms.size())
				error("Size is wrong, we don't handle this now...");

			for (Model::SymbolList_t::const_iterator it = syms.begin();
					it != syms.end();
					++it) {
				ISymbol *cur = *it;

				if (cur->getType() == ISymbol::SYM_TEXT) {
					fillCacheWithSymbol(syms.front());
					break;
				}
			}
		}

		IInstruction *p = m_instructionCache[curAddress];
		if (!p)
			break;

		if (p->getSize() == 0)
			break;

		out.push_back(p);

		curAddress = p->getAddress() + p->getSize();
	}
	m_mutex.unlock();

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

		if (cur->getBranchTargetAddress() != IInstruction::INVALID_ADDRESS)
			m_crossReferences[cur->getBranchTargetAddress()].push_back(cur->getAddress());

		// Fill the file:line cache with this instruction
		getLineByAddressLocked(cur->getAddress());
	}
}

void Model::worker(unsigned queueNr)
{
	SymbolQueue_t *queue = &m_workQueues[queueNr];

	while (queue->size() != 0) {
		ISymbol *cur = queue->front();

		fillCacheWithSymbol(cur);

		queue->pop_front();
	}
}

bool Model::parsingComplete()
{
	unsigned cores = get_number_of_cores();

	for (unsigned i = 0; i < cores; i++) {
		if (!m_workQueues[i].empty())
			return false;
	}

	return true;
}

void Model::parseAll()
{
	unsigned cores = get_number_of_cores();
	unsigned curCore = 0;

	// Fill work queues
	(void)getSymbols();
	for (SymbolList_t::iterator it = m_symbols.begin();
			it != m_symbols.end();
			++it, ++curCore) {
		ISymbol *cur = *it;

		if (curCore == cores)
			curCore = 0;

		if (cur->getType() != ISymbol::SYM_TEXT)
			continue;

		m_workQueues[curCore].push_back(cur);
	}

	// Create threads for all queues
	for (unsigned i = 0; i < cores; i++)
		m_threads[i] = new std::thread(&Model::worker, this, i);
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
	m_mutex.lock();
	m_symbolsByAddress[sym.getAddress()].push_back(&sym);
	m_orderedSymbols[sym.getAddress()].push_back(&sym);
	m_mutex.unlock();
}

const Model::SymbolList_t &Model::getSymbolsLocked()
{
	if (m_symbols.size() != 0)
		return m_symbols;

	for (Model::SymbolOrderedMap_t::iterator it = m_orderedSymbols.begin();
			it != m_orderedSymbols.end();
			++it) {
		Model::SymbolList_t syms = it->second;

		for (Model::SymbolList_t::iterator sIt = syms.begin();
				sIt != syms.end();
				++sIt) {
			ISymbol *cur = *sIt;

			m_symbols.push_back(cur);
		}
	}

	return m_symbols;
}

const Model::SymbolList_t &Model::getSymbols()
{
	m_mutex.lock();
	const Model::SymbolList_t &out = getSymbolsLocked();
	m_mutex.unlock();

	return out;
}

const Model::SymbolList_t Model::getSymbolExactLocked(uint64_t address)
{
	if (m_symbolsByAddress.find(address) != m_symbolsByAddress.end())
		return m_symbolsByAddress[address];

	return Model::SymbolList_t();
}

const Model::SymbolList_t Model::getNearestSymbolLocked(uint64_t address)
{
	Model::SymbolMap_t::const_iterator exactIt = m_symbolsByAddress.find(address);

	if (exactIt != m_symbolsByAddress.end())
		return exactIt->second;

	SymbolOrderedMap_t::iterator it = m_orderedSymbols.lower_bound(address);
	Model::SymbolList_t out;

	if (m_orderedSymbols.empty())
		return out;

	--it;

	// Above the last symbol
	if (it == m_orderedSymbols.end())
		return out;

	for (Model::SymbolList_t::iterator sIt = it->second.begin();
			sIt != it->second.end();
			++sIt) {
		ISymbol *cur = *sIt;

		if (cur->getAddress() + cur->getSize() < address)
			continue;

		out.push_back(cur);
	}

	return out;
}

const Model::SymbolList_t Model::getSymbolExact(uint64_t address)
{
	m_mutex.lock();
	const Model::SymbolList_t out = getSymbolExactLocked(address);
	m_mutex.unlock();

	return out;
}

const Model::SymbolList_t Model::getNearestSymbol(uint64_t address)
{
	m_mutex.lock();
	const Model::SymbolList_t out = getNearestSymbolLocked(address);
	m_mutex.unlock();

	return out;
}

const ILineProvider::FileLine Model::getLineByAddressLocked(uint64_t addr)
{
	if (m_fileLineCache.find(addr) != m_fileLineCache.end())
	{
		return m_fileLineCache[addr];
	}

	// Return nothing
	if (!SymbolFactory::instance().getLineProvider())
		m_fileLineCache[addr] = ILineProvider::FileLine();
	else
		m_fileLineCache[addr] = SymbolFactory::instance().getLineProvider()->getLineByAddress(addr);

	return m_fileLineCache[addr];
}

const ILineProvider::FileLine Model::getLineByAddress(uint64_t addr)
{
	m_mutex.lock();
	const ILineProvider::FileLine out = getLineByAddressLocked(addr);
	m_mutex.unlock();

	return out;
}

const Model::CrossReferenceList_t &Model::getReferences(uint64_t addr) const
{
	Model::CrossReferenceMap_t::const_iterator it = m_crossReferences.find(addr);

	if (it != m_crossReferences.end())
		return it->second;

	return m_emptyReferenceList;
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

