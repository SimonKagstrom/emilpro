#include "emilpro/database.hh"

#include "emilpro/i_binary_parser.hh"

#include <fmt/format.h>

using namespace emilpro;

bool
Database::ParseFile(std::unique_ptr<IBinaryParser> parser,
                    std::unique_ptr<IDisassembler> disassembler)
{
    m_disassembler = std::move(disassembler);

    parser->ForAllSections([this](auto section) {
        m_sections.push_back(std::move(section));
        m_section_refs.push_back(*m_sections.back());
    });

    // Disassemble all sections
    for (auto& section : m_sections)
    {
        section->Disassemble(*m_disassembler);

        std::ranges::copy(section->Symbols(), std::back_inserter(m_symbol_refs));
        std::ranges::copy(section->Instructions(), std::back_inserter(m_instruction_refs));
    }

    // Calculate referenced by
    std::vector<std::pair<std::reference_wrapper<IInstruction>, IInstruction::Referer>>
        all_refers_to;
    for (auto& insn_ref : m_instruction_refs)
    {
        auto& insn = insn_ref.get();
        auto refers_to = insn.RefersTo();
        if (refers_to)
        {
            if (!refers_to->symbol && insn.Type() == IInstruction::InstructionType::kCall)
            {
                FixupCallRefersTo(insn, *refers_to);
            }

            all_refers_to.push_back({insn, *refers_to});
        }
    }

    for (auto& [insn_ref, ref] : all_refers_to)
    {
        auto& insn = insn_ref.get();
        auto& hint = insn.Section();

        if (hint.ContainsAddress(hint.StartAddress() + ref.offset))
        {
            if (auto dst = hint.InstructionAt(ref.offset))
            {
                dst->AddReferredBy(hint, insn.Offset(), nullptr);
            }
        }
    }

    m_parsers.push_back(std::move(parser));

    return true;
}

std::span<const std::reference_wrapper<ISection>>
Database::Sections() const
{
    return m_section_refs;
}

std::span<const std::reference_wrapper<ISymbol>>
Database::Symbols() const
{
    return m_symbol_refs;
}

std::vector<Database::LookupResult>
Database::LookupByAddress(const ISection* hint, uint64_t address)
{
    if (hint && hint->ContainsAddress(address))
    {
        return {
            Database::LookupResult {*hint,
                                    address - hint->StartAddress(),
                                    SymbolBySectionOffset(*hint, address - hint->StartAddress())}};
    }

    for (const auto& section : m_sections)
    {
        if (section->ContainsAddress(address))
        {
            return {Database::LookupResult {
                *section,
                address - section->StartAddress(),
                SymbolBySectionOffset(*section, address - section->StartAddress())}};
        }
    }

    return {};
}

std::vector<Database::LookupResult>
Database::LookupByName(std::string_view name)
{
    return {};
}


std::optional<std::reference_wrapper<const ISymbol>>
Database::SymbolBySectionOffset(const ISection& section, uint64_t offset)
{
    // TODO: use std::lower_bound by offset here instead
    for (auto& sym_ref : section.Symbols())
    {
        const auto& sym = sym_ref.get();

        if (offset >= sym.Offset() && offset < sym.Offset() + sym.Size())
        {
            return sym;
        }
    }

    return std::nullopt;
}

void
Database::FixupCallRefersTo(IInstruction& insn, const IInstruction::Referer& refers_to)
{
    auto results = LookupByAddress(refers_to.section, refers_to.offset);

    for (auto& cur : results)
    {
        const ISymbol* sym = nullptr;

        if (cur.symbol)
        {
            sym = &cur.symbol->get();
        }

        insn.SetRefersTo(cur.section, cur.offset, sym);
    }
}