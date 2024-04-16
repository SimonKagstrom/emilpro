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

    virtual std::string_view Name() const = 0;

    virtual uint64_t StartAddress() const = 0;

    virtual size_t Size() const = 0;

    virtual Type GetType() const = 0;
};

} // namespace emilpro
