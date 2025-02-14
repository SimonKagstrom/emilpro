#include "emilpro/address_history.hh"

using namespace emilpro;

AddressHistory::AddressHistory()
{
    // Avoid reallocations for the span
    m_entries.reserve(512);
}

void
AddressHistory::PushEntry(const ISection& section, uint64_t offset, uint32_t row)
{
    if (m_entries.empty() == false && m_index != m_entries.size() - 1)
    {
        m_entries.resize(m_index);
    }
    m_entries.push_back({&section, offset, row});
    m_index = m_entries.size() - 1;
}

void
AddressHistory::SetIndex(int index)
{
    if (index >= 0)
    {
        m_index = std::min(static_cast<size_t>(index), m_entries.size() - 1);
    }
}

unsigned
AddressHistory::CurrentIndex() const
{
    return m_index;
}

void
AddressHistory::Clear()
{
    m_entries.clear();
    m_index = 0;
}

// Valid until a new entry is pushed
std::span<const AddressHistory::Entry>
AddressHistory::Entries() const
{
    return m_entries;
}
