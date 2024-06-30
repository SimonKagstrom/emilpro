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

    virtual std::span<const std::string> UsedRegisters() const = 0;

    virtual std::optional<std::pair<std::string_view, uint32_t>> GetSourceLocation() const = 0;

    virtual const ISection& Section() const = 0;

    virtual const ISymbol* Symbol() const = 0;

    // Modifying methods (used when parsing the binary)

    /**
     * @brief Set the high-level source file for this instruction
     *
     * @param file the file
     * @param line the line
     */
    virtual void SetSourceLocation(std::string_view file, uint32_t line) = 0;

    /**
     * @brief Set the symbols/offsets this instruction refers to
     *
     * @param section the section of the destination
     * @param offset the offset of the destination instruction
     * @param symbol the symbol (if resolved) of the destination
     */
    virtual void SetRefersTo(const ISection& section, uint64_t offset, const ISymbol* symbol) = 0;

    /**
     * @brief Set the incoming references for this instruction
     *
     * @param section the source section of the reference
     * @param offset the source offset of the reference
     * @param symbol the source symbol of the reference
     */
    virtual void AddReferredBy(const ISection& section, uint64_t offset, const ISymbol* symbol) = 0;

    /**
     * @brief Commit the modifiable data for this instruction
     *
     * Until then, @a RefersTo etc will return empty values
     */
    virtual void Commit() = 0;
};

} // namespace emilpro
