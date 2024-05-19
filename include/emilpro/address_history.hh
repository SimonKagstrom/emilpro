#pragma once

#include "i_section.hh"

#include <vector>

namespace emilpro
{

class AddressHistory
{
public:
    struct Entry
    {
        const ISection* section {nullptr};
        uint64_t offset;

        auto operator==(const Entry& other)
        {
            return section == other.section && offset == other.offset;
        }
    };

    AddressHistory();

    void PushEntry(const ISection& section, uint64_t offset);

    void SetIndex(unsigned index);

    unsigned CurrentIndex() const;

    void Clear();

    // Valid until a new entry is pushed
    std::span<const Entry> Entries() const;

private:
    std::vector<Entry> m_entries;
    unsigned m_index {0};
};

} // namespace emilpro
