#include <addresshistory.hh>
#include <model.hh>

using namespace emilpro;

class EntryImpl : public AddressHistory::Entry
{
public:
	EntryImpl(std::string name, uint64_t address, bool valid) :
		m_valid(valid),
		m_name(name),
		m_address(address)
	{
	}

	std::string getName() const
	{
		return m_name;
	}

	uint64_t getAddress() const
	{
		return m_address;
	}

	bool isValid() const
	{
		return m_valid;
	}

private:
	bool m_valid;
	std::string m_name;
	uint64_t m_address;
};


AddressHistory::AddressHistory() :
		m_currentEntry(-1)
{
	m_sentinel = new EntryImpl("Bruce Lee by Datasoft", 0, false);
}

AddressHistory::~AddressHistory()
{
	clear();
	delete m_sentinel;
}

bool AddressHistory::maybeAddEntry(uint64_t address)
{
	Model &model = Model::instance();

	Model::SymbolList_t syms = model.getNearestSymbol(address);
	if (syms.empty())
		return false;

	unsigned i = 0;
	std::string name;
	for (Model::SymbolList_t::iterator it = syms.begin();
			it != syms.end();
			++it) {
		ISymbol *cur = *it;

		name += cur->getName();
		i++;

		if (i < syms.size())
			name += " / ";
	}

	EntryImpl *cur = new EntryImpl(name, address, true);

	if ((m_currentEntry == (int)m_entries.size() -1) || m_currentEntry == -1)
		m_currentEntry = m_entries.size();

	m_entries.push_back(cur);

	return true;
}

const AddressHistory::Entry& AddressHistory::current()
{
	if (m_currentEntry == -1)
		return *m_sentinel;

	return *m_entries[m_currentEntry];
}

const AddressHistory::Entry& AddressHistory::back()
{
	if (m_entries.size() == 0)
		return *m_sentinel;

	if (m_currentEntry <= 0)
		return *m_sentinel;

	m_currentEntry--;

	return *m_entries[m_currentEntry];
}

const AddressHistory::Entry& AddressHistory::forward()
{
	if (m_entries.size() == 0)
		return *m_sentinel;

	m_currentEntry++;

	if (m_currentEntry >= (int)m_entries.size())
		return *m_sentinel;

	return *m_entries[m_currentEntry];
}

void AddressHistory::clear()
{
	m_currentEntry = -1;

	for (unsigned i = 0; i < m_entries.size(); i++) {
		AddressHistory::Entry *cur = m_entries[i];

		delete cur;
	}

	m_entries.clear();
}
