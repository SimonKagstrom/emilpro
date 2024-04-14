#include "section.hh"

#include "emilpro/i_disassembler.hh"

#include <fmt/format.h>
#include <vector>

using namespace emilpro;

Section::Section(std::span<const std::byte> data, uint64_t start_address, Type type)
    : m_data(data.begin(), data.end())
    , m_start_address(start_address)
    , m_type(type)
{
    fmt::print("Section created with start address {:x} and size {:x}\n", start_address, data.size());
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
Section::AddRelocation(uint64_t offset, const Symbol& symbol)
{
    fmt::print("Sec add reloc to sym {}. Offset {}\n", symbol.GetDemangledName(), offset);
    m_relocations.push_back(symbol);
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

            last_offset = symbol->GetOffset();
        }
    }
}

void
Section::Disassemble(IDisassembler& disassembler)
{
    // Should already be done, but anyway
    m_instruction_refs.clear();
    m_instructions.clear();

    disassembler.Disassemble(Data(), StartAddress(), [this](auto insn) {
        m_instructions.push_back(std::move(insn));
    });

    for (auto& insn : m_instructions)
    {
        m_instruction_refs.push_back(*insn);
    }
}

std::span<const std::reference_wrapper<IInstruction>>
Section::GetInstructions() const
{
    return m_instruction_refs;
}


std::unique_ptr<ISection>
ISection::Create(std::span<const std::byte> data, uint64_t start_address, Type type)
{
    return std::make_unique<Section>(data, start_address, type);
}
