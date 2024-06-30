#pragma once

#include "i_instruction.hh"

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

    virtual const std::string& Flags() const = 0;

    virtual const std::string& Name() const = 0;

    virtual const std::string& DemangledName() const = 0;

    virtual std::span<const IInstruction::Referer> ReferredBy() const = 0;

    virtual std::span<const IInstruction::Referer> RefersTo() const = 0;

    virtual std::span<const std::reference_wrapper<IInstruction>> Instructions() const = 0;


    virtual void WaitForCommit() = 0;
};

} // namespace emilpro
