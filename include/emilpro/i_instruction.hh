#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace emilpro
{
class ISection;

class IInstruction
{
public:
    virtual ~IInstruction() = default;

    virtual std::span<const std::byte> Data() const = 0;

    virtual uint32_t Offset() const = 0;

    virtual std::string_view AsString() const = 0;

    virtual std::span<const uint64_t> GetReferredBy() const = 0;

    virtual std::span<const uint64_t> GetRefersTo() const = 0;

    virtual std::span<std::string_view> GetUsedRegisters() const = 0;

    virtual std::optional<std::pair<std::string_view, uint32_t>> GetSourceLocation() const = 0;

    virtual const ISection& Section() const = 0;

    virtual void SetSourceLocation(std::string_view file, uint32_t line) = 0;

    virtual void SetSection(ISection &section) = 0;
};

} // namespace emilpro
