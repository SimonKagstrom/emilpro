#include "section.hh"

#include <fmt/format.h>
#include <vector>

using namespace emilpro;

Section::Section(std::span<const std::byte> data, uint64_t start_address, Type type)
    : m_data(data.begin(), data.end())
    , m_start_address(start_address)
    , m_type(type)
{
}

std::span<const std::byte>
Section::Data() const
{
    return m_data;
}

uint64_t
Section::StartAddress() const
{
    return m_start_address;
}

size_t
Section::Size() const
{
    return m_data.size();
}

ISection::Type
Section::GetType() const
{
    return m_type;
}

void
Section::AddSymbol(std::unique_ptr<Symbol> symbol)
{
    m_sorted_symbols[symbol->GetOffset()].push_back(symbol.get());
    m_symbols.push_back(std::move(symbol));
}

void
Section::FixupSymbolSizes()
{
    size_t last_offset = Size();

    for (auto it = m_sorted_symbols.rbegin(); it != m_sorted_symbols.rend(); ++it)
    {
        auto& symbols = it->second;

        auto adjust = last_offset;
        for (auto* symbol : symbols)
        {
            symbol->SetSize(adjust - symbol->GetOffset());

            fmt::print("Symbol {} @{:08x} size: {:x}. Last offset {:x} and section size {:x}\n",
                       symbol->GetDemangledName(),
                       symbol->GetOffset(),
                       symbol->Size(),
                       adjust,
                       Size());
            last_offset = symbol->GetOffset();
        }
    }
}

std::unique_ptr<ISection>
ISection::Create(std::span<const std::byte> data, uint64_t start_address, Type type)
{
    return std::make_unique<Section>(data, start_address, type);
}
