#pragma once

#include "i_binary_parser.hh"
#include "i_disassembler.hh"

#include <string>
#include <vector>

namespace emilpro
{

class ISection;
class ISymbol;
class IInstruction;

class Database
{
public:
    struct LookupResult
    {
        ISection& section;
        uint64_t offset;
        std::optional<std::reference_wrapper<const ISymbol>> symbol;
        std::optional<std::span<std::reference_wrapper<const IInstruction>>> instructions;
    };

    bool ParseFile(std::string_view file_path);

    std::span<const std::reference_wrapper<ISection>> GetSections() const;

    std::vector<LookupResult> LookupByAddress(uint64_t address);

    std::vector<LookupResult> LookupByName(std::string_view name);

private:
    std::vector<std::unique_ptr<IBinaryParser>> m_parsers;
    std::unique_ptr<IDisassembler> m_disassembler;

    std::vector<std::unique_ptr<ISection>> m_sections;
    std::vector<std::reference_wrapper<ISection>> m_section_refs;
};

} // namespace emilpro
