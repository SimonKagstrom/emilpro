#pragma once

#include "i_binary_parser.hh"
#include "i_disassembler.hh"

#include <optional>

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
        ISection &section;
        std::optional<std::reference_wrapper<ISymbol>> symbol;
        std::optional<std::span<const IInstruction>> instructions;
    };

    Database(std::unique_ptr<IDisassembler> disassembler);

    void ParseFile(std::unique_ptr<IBinaryParser> parser);

    std::optional<LookupResult> LookupByAddress(uint64_t address);

    std::optional<LookupResult> LookupByName(std::string_view name);
};

} // namespace emilpro
