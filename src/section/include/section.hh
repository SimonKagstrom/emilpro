#pragma once

#include "emilpro/i_instruction.hh"
#include "emilpro/i_section.hh"
#include "symbol.hh"

#include <functional>
#include <map>
#include <memory>
#include <vector>

namespace emilpro
{

class Section : public ISection
{
public:
    struct FileLine
    {
        std::string_view file;
        uint32_t line;
    };

    Section(std::string_view name,
            std::span<const std::byte> data,
            uint64_t start_address,
            Type type,
            std::function<std::optional<FileLine>(uint64_t offset)> line_lookup);

    void AddSymbol(std::unique_ptr<Symbol> symbol);
    void AddRelocation(uint64_t offset, const Symbol& symbol);
    void FixupSymbolSizes();

private:
    void Disassemble(IDisassembler& disassembler) final;

    std::span<const std::reference_wrapper<IInstruction>> GetInstructions() const final;

    std::span<const std::byte> Data() const final;

    std::string_view Name() const final;

    uint64_t StartAddress() const final;

    size_t Size() const final;

    Type GetType() const final;


    const std::vector<std::byte> m_data;
    const uint64_t m_start_address;
    const Type m_type;
    const std::string m_name;
    std::function<std::optional<FileLine>(uint64_t offset)> m_line_lookup;

    std::vector<std::unique_ptr<Symbol>> m_symbols;
    std::map<uint64_t, std::vector<Symbol*>> m_sorted_symbols;
    std::vector<std::reference_wrapper<const Symbol>> m_relocations;

    std::vector<std::unique_ptr<IInstruction>> m_instructions;
    std::vector<std::reference_wrapper<IInstruction>> m_instruction_refs;
};

} // namespace emilpro
