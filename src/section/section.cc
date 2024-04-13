#include "section.hh"

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
Section::AddSymbol(std::unique_ptr<ISymbol> symbol)
{
    m_symbols.push_back(std::move(symbol));
}


std::unique_ptr<ISection>
ISection::Create(std::span<const std::byte> data, uint64_t start_address, Type type)
{
    return std::make_unique<Section>(data, start_address, type);
}
