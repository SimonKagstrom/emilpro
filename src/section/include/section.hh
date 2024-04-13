#pragma once

#include "emilpro/i_section.hh"
#include "symbol.hh"

#include <memory>
#include <vector>
#include <map>

namespace emilpro
{

class Section : public ISection
{
public:
    Section(std::span<const std::byte> data, uint64_t start_address, Type type);

    void AddSymbol(std::unique_ptr<Symbol> symbol);
    void FixupSymbolSizes();

private:
    std::span<const std::byte> Data() const final;

    uint64_t StartAddress() const final;

    size_t Size() const final;

    Type GetType() const final;

    const std::vector<std::byte> m_data;
    const uint64_t m_start_address;
    const Type m_type;

    std::vector<std::unique_ptr<Symbol>> m_symbols;
    std::map<uint64_t, std::vector<Symbol*>> m_sorted_symbols;
};

} // namespace emilpro
