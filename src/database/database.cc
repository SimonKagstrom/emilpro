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
    for (auto& insn : m_instruction_refs)
    {
        auto refers_to = insn.get().RefersTo();
        if (refers_to)
        {
            all_refers_to.push_back({insn, *refers_to});
        }
    }

    for (auto& [insn_ref, ref] : all_refers_to)
    {
        auto& insn = insn_ref.get();
        auto& hint = insn.Section();

        if (hint.ContainsAddress(ref.offset))
        {
            if (auto dst = hint.InstructionAt(ref.offset))
            {
                fmt::print("REF {} to {}\n", insn.Offset(), dst->Offset());
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
        return {Database::LookupResult {*hint, address - hint->StartAddress(), {}}};
    }

    for (auto& section : m_sections)
    {
        if (section->ContainsAddress(address))
        {
            return {Database::LookupResult {*section, address - section->StartAddress(), {}}};
        }
    }

    return {};
}

std::vector<Database::LookupResult>
Database::LookupByName(std::string_view name)
{
    return {};
}
