#include "emilpro/i_section.hh"
#include "emilpro/i_symbol.hh"

#include <vector>

#pragma once

namespace emilpro
{

class Symbol : public ISymbol
{
public:
    Symbol(const ISection& section, uint64_t offset, std::string_view flags, std::string_view name);

    void SetSize(size_t size);

private:
    std::span<const std::byte> Data() const final;
    const ISection& GetSection() final;
    uint64_t StartAddress() const final;
    size_t Size() const final;
    std::string_view GetFlags() const final;
    std::string_view GetName() const final;
    std::string_view GetDemangledName() const final;

    const ISection& m_section;
    const uint64_t m_offset;
    size_t m_size {0};
    std::string m_flags;
    std::string m_name;
    std::string m_demanged_name;
};

} // namespace emilpro
