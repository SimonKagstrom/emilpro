#include "../i_symbol.hh"

#include <trompeloeil.hpp>

namespace emilpro::mock
{

class MockSymbol : public ISymbol
{
public:
    MAKE_CONST_MOCK0(Name, const std::string&(), final);
    MAKE_CONST_MOCK0(DemangledName, const std::string&(), final);
    MAKE_CONST_MOCK0(Offset, uint64_t(), final);
    MAKE_CONST_MOCK0(Size, size_t(), final);
    MAKE_CONST_MOCK0(Section, (const ISection&)(), final);
    MAKE_CONST_MOCK0(Data, std::span<const std::byte>(), final);
    MAKE_CONST_MOCK0(Flags, const std::string&(), final);
    MAKE_CONST_MOCK0(Instructions,
                     (std::span<const std::reference_wrapper<IInstruction>>)(),
                     final);
    MAKE_CONST_MOCK0(ReferredBy, std::span<const IInstruction::Referer>(), final);
    MAKE_CONST_MOCK0(RefersTo, std::span<const IInstruction::Referer>(), final);

    MAKE_MOCK0(WaitForCommit, void());
};

} // namespace emilpro::mock
