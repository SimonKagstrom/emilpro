#pragma once

#include "i_binary_parser.hh"
#include "i_disassembler.hh"

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
        std::optional<std::reference_wrapper<const ISymbol>> symbol;
        std::optional<std::span<std::reference_wrapper<const IInstruction>>> instructions;
    };

    Database(std::unique_ptr<IDisassembler> disassembler);

    void ParseFile(std::unique_ptr<IBinaryParser> parser);

    std::span<const std::reference_wrapper<const ISection>> GetSections() const;

    std::vector<LookupResult> LookupByAddress(uint64_t address);

    std::vector<LookupResult> LookupByName(std::string_view name);
};

} // namespace emilpro
