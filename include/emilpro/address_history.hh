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
        uint32_t row {0};

        bool operator==(const Entry& other) const = default;
    };

    AddressHistory();

    void PushEntry(const ISection& section, uint64_t offset, uint32_t row);

    void SetIndex(int index);

    void Forward()
    {
        SetIndex(m_index + 1);
    }

    void Backward()
    {
        SetIndex(m_index - 1);
    }

    unsigned CurrentIndex() const;

    void Clear();

    // Valid until a new entry is pushed
    std::span<const Entry> Entries() const;

private:
    std::vector<Entry> m_entries;
    int m_index {0};
};

} // namespace emilpro
