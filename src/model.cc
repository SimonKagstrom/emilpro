#include <model.hh>
#include <symbolfactory.hh>
#include <isymbolprovider.hh>
#include <idisassembly.hh>
#include <utils.hh>

#include <unordered_map>
#include <map>

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
		m_parsingComplete(false),
		m_quit(false)
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

	m_quit = true;

	for (unsigned i = 0; i < cores; i++) {
		if (m_threads[i])
			m_threads[i]->join();

		delete m_threads[i];
	}

	delete[] m_threads;
	delete[] m_workQueues;

	for (InstructionMap_t::iterator it = m_instructionCache.begin();
			it != m_instructionCache.end();
			++it) {
		IInstruction *p = it->second;

		delete p;
	}

	for (DataMap_t::iterator it = m_data.begin();
			it != m_data.end();
			++it) {
		DataChunk *cur = it->second;

		delete cur;
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
	InstructionList_t cleanupList;

	for (InstructionList_t::iterator it = lst.begin();
			it != lst.end();
			++it) {
		IInstruction *cur = *it;

		// We can have multiple overlapping symbols (typically sections/normal syms)
		if (m_instructionCache[cur->getAddress()]) {
			cleanupList.push_back(cur);

			continue;
		}

		m_instructionCache[cur->getAddress()] = cur;

		if (cur->getBranchTargetAddress() != IInstruction::INVALID_ADDRESS)
			m_crossReferences[cur->getBranchTargetAddress()].push_back(cur->getAddress());

		// Fill the file:line cache with this instruction
		getLineByAddressLocked(cur->getAddress());
	}

	if (sym->getType() == ISymbol::SYM_SECTION)
		deriveSymbols(sym, lst);

	// Cleanup overlapped insns
	for (InstructionList_t::iterator it = cleanupList.begin();
			it != cleanupList.end();
			++it) {
		delete *it;
	}
}

void Model::deriveSymbols(ISymbol *sym, InstructionList_t &lst)
{
	typedef std::map<uint64_t, bool> PossibleSiteMap_t;
	PossibleSiteMap_t possibleSites;
	uint64_t lastInsnAddr = 0;
	uint8_t *p = (uint8_t *)sym->getDataPtr();

	for (InstructionList_t::iterator it = lst.begin();
			it != lst.end();
			++it) {
		IInstruction *cur = *it;
		uint64_t endAddr = cur->getAddress() + cur->getSize();

		if (endAddr > lastInsnAddr)
			lastInsnAddr = endAddr;

		if (cur->getType() != IInstruction::IT_CALL)
			continue;

		uint64_t tgt = cur->getBranchTargetAddress();
		if (tgt != IInstruction::INVALID_ADDRESS) {
			if (m_symbolsByAddress[tgt].empty())
				possibleSites[tgt] = true;
		}
	}

	PossibleSiteMap_t::iterator lastIt = possibleSites.end();

	for (PossibleSiteMap_t::iterator it = possibleSites.begin();
			it != possibleSites.end();
			++it) {
		// Update size
		if (lastIt != possibleSites.end()) {
			uint64_t cur = it->first;
			uint64_t last = lastIt->first;

			addDerivedSymbol(last, cur - last, p + last);
		}

		lastIt = it;
	}

	if (lastIt == possibleSites.end())
		return;

	// Add the final entry
	uint64_t startLast = lastIt->first;
	uint64_t endLast = lastInsnAddr;

	addDerivedSymbol(startLast, endLast - startLast, p + startLast);
}

void Model::addDerivedSymbol(uint64_t address, int64_t size, void *data)
{
	if (size <= 0)
		return;

	ISymbol &sym = SymbolFactory::instance().createSymbol(ISymbol::LINK_NORMAL,
			ISymbol::SYM_TEXT,
			fmt("fn_0x%llx_0x%llx", (unsigned long long)address, (unsigned long long)(address + size)).c_str(),
			data, address, size, true, false, true);

	onSymbol(sym);
	m_pendingListenerSymbols.push_back(&sym);
}

void Model::worker(unsigned queueNr)
{
	SymbolQueue_t *queue = &m_workQueues[queueNr];

	while (queue->size() != 0 && !m_quit) {
		ISymbol *cur = queue->front();

		m_mutex.lock();
		fillCacheWithSymbol(cur);
		m_mutex.unlock();

		queue->pop_front();
	}

	unsigned cores = get_number_of_cores();
	bool parsingComplete = true;

	m_mutex.lock();
	for (unsigned i = 0; i < cores; i++) {
		if (m_workQueues[i].size() != 0)
			parsingComplete = false;
	}
	m_parsingComplete = parsingComplete;
	m_mutex.unlock();

	if (!parsingComplete)
		return;

	for (SymbolList_t::iterator it = m_pendingListenerSymbols.begin();
			it != m_pendingListenerSymbols.end();
			++it) {
		ISymbol &sym = **it;

		for (SymbolListeners_t::iterator lIt = m_symbolListeners.begin();
				lIt != m_symbolListeners.end();
				++lIt) {
			ISymbolListener *curListener = *lIt;

			curListener->onSymbol(sym);
		}
	}
}

bool Model::parsingComplete()
{
	bool out;

	m_mutex.lock();
	out = m_parsingComplete;
	m_mutex.unlock();

	return out;
}


bool Model::parsingOngoing()
{
	unsigned cores = get_number_of_cores();
	bool out = false;

	m_mutex.lock();
	for (unsigned i = 0; i < cores; i++) {
		if (m_workQueues[i].size() != 0)
			out = true;
	}
	if (m_parsingComplete && !out)
		out = false;

	m_mutex.unlock();

	return out;
}

void Model::parseAll()
{
	unsigned cores = get_number_of_cores();
	unsigned curCore = 0;
	SymbolList_t sectionSyms;

	// Fill work queues
	(void)getSymbols();

	if (parsingOngoing()) {
		for (SymbolList_t::iterator it = m_symbols.begin();
				it != m_symbols.end();
				++it, ++curCore) {
			ISymbol *cur = *it;

			for (SymbolListeners_t::iterator it = m_symbolListeners.begin();
					it != m_symbolListeners.end();
					++it) {
				ISymbolListener *curListener = *it;

				curListener->onSymbol(*cur);
			}
		}

		return;
	}

	m_pendingListenerSymbols.clear();
	for (SymbolList_t::iterator it = m_symbols.begin();
			it != m_symbols.end();
			++it, ++curCore) {
		ISymbol *cur = *it;

		for (SymbolListeners_t::iterator it = m_symbolListeners.begin();
				it != m_symbolListeners.end();
				++it) {
			ISymbolListener *curListener = *it;

			curListener->onSymbol(*cur);
		}

		// No need to reparse these then, but signal the listeners
		if (parsingComplete())
			continue;

		if (!cur->isExecutable())
			continue;

		if (cur->getType() == ISymbol::SYM_SECTION) {
			sectionSyms.push_back(cur);
			continue;
		}

		if (curCore >= cores)
			curCore = 0;

		m_workQueues[curCore].push_back(cur);
	}

	if (parsingComplete())
		return;

	// Place section symbols last (takes a long time to disassemble)
	for (SymbolList_t::iterator it = sectionSyms.begin();
			it != sectionSyms.end();
			++it) {
		ISymbol *cur = *it;

		m_workQueues[0].push_back(cur);
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

		if (cur->getType() != IInstruction::IT_CFLOW && cur->getType() != IInstruction::IT_CALL)
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


void Model::registerSymbolListener(ISymbolListener* listener)
{
	m_symbolListeners.push_back(listener);
}

void Model::onSymbol(ISymbol &sym)
{
	bool locked;

	locked = m_mutex.try_lock();
	if (sym.getType() == ISymbol::SYM_SECTION) {
		m_data[sym.getAddress()] = new DataChunk(sym.getAddress(),
						0, sym.getSize(), (uint8_t *)sym.getDataPtr());
	}

	m_symbolsByAddress[sym.getAddress()].push_back(&sym);
	m_orderedSymbols[sym.getAddress()].push_back(&sym);
	if (locked)
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

const uint8_t* Model::getData(uint64_t start, size_t size,
		uint64_t *returnedAddr, size_t *returnedSize)
{
	DataMap_t::iterator it = m_data.lower_bound(start);

	if (it == m_data.end())
		--it;

	if (it != m_data.begin())
		--it;

	DataChunk *cur = it->second;

	if (cur->m_address > start)
		return NULL;

	if (start - cur->m_address + size > cur->m_size)
		return NULL;

	if (returnedAddr)
		*returnedAddr = start;
	if (returnedSize)
		*returnedSize = size;

	return cur->m_data + (start - cur->m_address);
}

const uint8_t* Model::getSurroundingData(uint64_t address, size_t size,
		uint64_t* returnedStart, uint64_t* returnedEnd)
{
	DataMap_t::iterator it = m_data.lower_bound(address);

	if (it != m_data.begin())
		--it;

	DataChunk *cur = it->second;
	uint64_t start = address - size / 2;
	uint64_t end = address + size / 2;

	if (address > cur->m_address + cur->m_size)
		return NULL;

	if (end < cur->m_address)
		return NULL;

	if (start < cur->m_address)
		start = cur->m_address;
	if (end >= cur->m_address + cur->m_size)
		end = cur->m_address + cur->m_size;

	if (returnedStart)
		*returnedStart = start;
	if (returnedEnd)
		*returnedEnd = end;

	return cur->m_data + (start - cur->m_address);
}
