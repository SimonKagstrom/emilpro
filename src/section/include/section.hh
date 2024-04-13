#include "emilpro/i_section.hh"

#include <vector>

#pragma once

namespace emilpro
{

class Section : public ISection
{
public:
    Section(std::span<const std::byte> data, uint64_t start_address, Type type);

private:
    std::span<const std::byte> Data() const final;

    uint64_t StartAddress() const final;

    size_t Size() const final;

    Type GetType() const final;

    const std::vector<std::byte> m_data;
    const uint64_t m_start_address;
    const Type m_type;
};

} // namespace emilpro
