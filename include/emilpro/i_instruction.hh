#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace emilpro
{
class ISection;
class ISymbol;

class IInstruction
{
public:
    enum class InstructionType
    {
        kBranch,
        kCall,
        kOther,
    };

    struct Referer
    {
        const ISection* section;
        uint64_t offset;
        const ISymbol* symbol;
    };

    virtual ~IInstruction() = default;

    virtual std::span<const std::byte> Data() const = 0;

    virtual InstructionType Type() const = 0;

    virtual uint32_t Size() const = 0;

    virtual uint64_t Offset() const = 0;

    virtual std::string_view AsString() const = 0;

    virtual std::span<const Referer> ReferredBy() const = 0;

    virtual std::optional<Referer> RefersTo() const = 0;

    /// From relocations
    virtual void SetRefersTo(const ISection& section, uint64_t offset, const ISymbol* symbol) = 0;

    /// From instructions
    virtual void AddReferredBy(const ISection& section, uint64_t offset, const ISymbol* symbol) = 0;

    virtual std::span<const std::string> UsedRegisters() const = 0;

    virtual std::optional<std::pair<std::string_view, uint32_t>> GetSourceLocation() const = 0;

    virtual const ISection& Section() const = 0;

    virtual const ISymbol* Symbol() const = 0;

    virtual void SetSourceLocation(std::string_view file, uint32_t line) = 0;
};

} // namespace emilpro
