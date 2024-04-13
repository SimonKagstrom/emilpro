#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace emilpro
{

class IInstruction
{
public:
    virtual ~IInstruction() = default;

    virtual uint32_t GetOffset() const = 0;

    virtual std::string_view AsString() const = 0;

    virtual std::span<const uint64_t> GetReferredBy() const = 0;

    virtual std::span<const uint64_t> GetRefersTo() const = 0;

    virtual std::span<std::string_view> GetUsedRegisters() const = 0;
};

} // namespace emilpro
