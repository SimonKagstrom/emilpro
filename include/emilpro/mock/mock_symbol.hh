#include "../i_symbol.hh"

#include <trompeloeil.hpp>

namespace emilpro::mock
{

class MockSymbol : public ISymbol
{
public:
    MAKE_CONST_MOCK0(GetName, std::string_view(), final);
    MAKE_CONST_MOCK0(GetDemangledName, std::string_view(), final);
    MAKE_CONST_MOCK0(Offset, uint64_t(), final);
    MAKE_CONST_MOCK0(Size, uint64_t(), final);
    MAKE_CONST_MOCK0(Section, (const ISection&)(), final);
    MAKE_CONST_MOCK0(Data, std::span<const std::byte>(), final);
    MAKE_CONST_MOCK0(GetFlags, std::string_view(), final);
};

} // namespace emilpro::mock
