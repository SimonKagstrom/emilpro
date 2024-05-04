#include "section.hh"

#include "emilpro/i_disassembler.hh"

#include <fmt/format.h>
#include <vector>

using namespace emilpro;

Section::Section(std::string_view name,
                 std::span<const std::byte> data,
                 uint64_t start_address,
                 Type type,
                 std::function<std::optional<FileLine>(uint64_t offset)> line_lookup)
    : m_data(data.begin(), data.end())
    , m_start_address(start_address)
    , m_type(type)
    , m_name(name)
    , m_line_lookup(std::move(line_lookup))
{
    fmt::print("Section {} created with start address {:x} and size {:x}\n",
               m_name,
               start_address,
               data.size());
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

const std::string&
Section::Name() const
{
    return m_name;
}


void
Section::AddSymbol(std::unique_ptr<Symbol> symbol)
{
    m_sorted_symbols[symbol->Offset()].push_back(symbol.get());
    m_symbols.push_back(std::move(symbol));
}

void
Section::AddRelocation(uint64_t offset, const Symbol& symbol)
{
    fmt::print("Sec add reloc to sym {}. Offset {}\n", symbol.DemangledName(), offset);
    m_relocations.push_back({symbol, offset});
    m_sorted_relocations[offset] = &m_relocations.back();
}

void
Section::FixupSymbolSizes()
{
    size_t last_offset = Size();

    for (auto it = m_sorted_symbols.rbegin(); it != m_sorted_symbols.rend(); ++it)
    {
        const auto& symbols = it->second;

        auto adjust = last_offset;
        for (auto* symbol : symbols)
        {
            int64_t size = adjust - symbol->Offset();
            if (size >= 0)
            {
                symbol->SetSize(size);
            }

            last_offset = symbol->Offset();
            m_symbol_refs.push_back(*symbol);
        }
    }
}

void
Section::Disassemble(IDisassembler& disassembler)
{
    if (m_type != Type::kInstructions)
    {
        return;
    }

    // Should already be done, but anyway
    m_instruction_refs.clear();
    m_instructions.clear();

    for (auto& sym : m_symbols)
    {
        if (static_cast<int64_t>(sym->Offset()) < 0)
        {
            continue;
        }
        disassembler.Disassemble(*this,
                                 StartAddress() + sym->Offset(),
                                 sym->Data(),
                                 [this](auto insn) { m_instructions.push_back(std::move(insn)); });
    }

    ISymbol* current_symbol_ {nullptr};

    for (auto& insn : m_instructions)
    {
        auto file_line = m_line_lookup(insn->Offset());
        if (file_line)
        {
            insn->SetSourceLocation(file_line->file, file_line->line);
        }
        auto rel_it = m_sorted_relocations.lower_bound(insn->Offset());
        if (rel_it != m_sorted_relocations.end())
        {
            auto reloc_dst = rel_it->first;
            auto& sym = rel_it->second->symbol.get();
            auto insn_offset = insn->Offset();

            if (reloc_dst >= insn_offset && reloc_dst < insn_offset + insn->Size())
            {
                insn->SetRefersTo(sym.Section(), sym.Offset(), &sym);
            }
        }
        m_instruction_refs.push_back(*insn);
        m_sorted_instructions[insn->Offset()] = insn.get();
    }
}

std::span<const std::reference_wrapper<IInstruction>>
Section::Instructions() const
{
    return m_instruction_refs;
}

std::span<const std::reference_wrapper<ISymbol>>
Section::Symbols() const
{
    return m_symbol_refs;
}

bool
Section::ContainsAddress(uint64_t address) const
{
    auto start = StartAddress();

    return address >= start && address < start + Size();
}

IInstruction*
Section::InstructionAt(uint64_t offset) const
{
    if (auto it = m_sorted_instructions.find(offset); it != m_sorted_instructions.end())
    {
        return it->second;
    }

    return nullptr;
}