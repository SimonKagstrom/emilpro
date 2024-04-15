#pragma once

#include <cstdint>
#include <span>
#include <string>

namespace emilpro
{

class ISection;

class ISymbol
{
public:
    virtual ~ISymbol() = default;

    virtual std::span<const std::byte> Data() const = 0;

    virtual const ISection& Section() const = 0;

    /// Relative to the section
    virtual uint64_t Offset() const = 0;

    virtual size_t Size() const = 0;

    virtual size_t InstructionCount() const = 0;

    virtual std::string_view GetFlags() const = 0;

    virtual std::string_view GetName() const = 0;

    virtual std::string_view GetDemangledName() const = 0;
};

} // namespace emilpro
