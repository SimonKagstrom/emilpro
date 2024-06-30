#pragma once

#include <cstdint>
#include <memory>
#include <span>

namespace emilpro
{

class IDisassembler;
class IInstruction;
class ISymbol;

class ISection
{
public:
    enum class Type
    {
        kData,
        kInstructions,
        kOther,
    };

    virtual ~ISection() = default;

    virtual void Disassemble(IDisassembler& disassembler) = 0;

    virtual std::span<const std::reference_wrapper<IInstruction>> Instructions() const = 0;

    /// Symbols for this section, sorted by offset
    virtual std::span<const std::reference_wrapper<ISymbol>> Symbols() const = 0;

    virtual std::span<const std::byte> Data() const = 0;

    virtual const std::string& Name() const = 0;

    virtual uint64_t StartAddress() const = 0;

    virtual size_t Size() const = 0;

    virtual Type GetType() const = 0;

    virtual const std::string& Flags() const = 0;

    virtual bool ContainsAddress(uint64_t address) const = 0;

    virtual IInstruction* InstructionAt(uint64_t) const = 0;

    /// Called after instructions cross-references have been calculated
    virtual void FixupCrossReferences() = 0;


    /// Hint to the disassembler that this symbol is needed urgently
    virtual void DisassemblyHint(ISymbol &sym) const = 0;
};

} // namespace emilpro
