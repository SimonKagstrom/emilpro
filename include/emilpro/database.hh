#pragma once

#include "emilpro/i_section.hh"
#include "emilpro/i_symbol.hh"
#include "i_binary_parser.hh"
#include "i_disassembler.hh"

#include <string>
#include <vector>
#include <thread>
#include <mutex>

namespace emilpro
{

class Database
{
public:
    ~Database();

    struct LookupResult
    {
        const ISection& section;
        uint64_t offset;
        std::optional<std::reference_wrapper<const ISymbol>> symbol;
        std::optional<std::span<std::reference_wrapper<const IInstruction>>> instructions;
    };

    bool ParseFile(std::unique_ptr<IBinaryParser> parser,
                   std::unique_ptr<IDisassembler> disassembler);

    std::span<const std::reference_wrapper<ISection>> Sections() const;

    std::span<const std::reference_wrapper<ISymbol>> Symbols() const;

    std::vector<LookupResult> LookupByAddress(const ISection* hint, uint64_t address);

private:
    void ParseThread();

    void FixupCallRefersTo(IInstruction& instruction, const IInstruction::Referer& referer);

    std::optional<std::reference_wrapper<const ISymbol>>
    SymbolBySectionOffset(const ISection& section, uint64_t offset);

    std::vector<std::unique_ptr<IBinaryParser>> m_parsers;
    std::unique_ptr<IDisassembler> m_disassembler;

    std::vector<std::unique_ptr<ISection>> m_sections;
    std::vector<std::reference_wrapper<ISection>> m_section_refs;

    std::vector<std::reference_wrapper<ISymbol>> m_symbol_refs;

    std::vector<std::reference_wrapper<IInstruction>> m_instruction_refs;

    std::thread m_parse_thread;
};

} // namespace emilpro
