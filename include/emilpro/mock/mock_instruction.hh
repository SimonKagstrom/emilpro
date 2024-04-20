#pragma once

#include "../i_instruction.hh"
#include "../i_section.hh"

#include <trompeloeil.hpp>

namespace emilpro::mock
{

class MockInstruction : public IInstruction
{
public:
    MAKE_CONST_MOCK0(Data, (std::span<const std::byte>)(), final);
    MAKE_CONST_MOCK0(Size, uint32_t(), final);
    MAKE_CONST_MOCK0(Offset, uint32_t(), final);
    MAKE_CONST_MOCK0(AsString, std::string_view(), final);
    MAKE_CONST_MOCK0(ReferredBy, std::span<const Referer>(), final);
    MAKE_CONST_MOCK0(RefersTo, std::optional<Referer>(), final);
    MAKE_MOCK3(SetRefersTo, void(const ISection&, uint64_t, const ISymbol*), final);
    MAKE_MOCK3(AddReferredBy,
               void(const ISection& section, uint64_t offset, const ISymbol* symbol),
               final);

    MAKE_CONST_MOCK0(GetUsedRegisters, std::span<std::string_view>(), final);
    MAKE_CONST_MOCK0(GetSourceLocation,
                     (std::optional<std::pair<std::string_view, uint32_t>>)(),
                     final);
    MAKE_CONST_MOCK0(Section, (const ISection&)(), final);
    MAKE_MOCK2(SetSourceLocation, void(std::string_view, uint32_t), final);
};

} // namespace emilpro::mock