#include "../i_binary_parser.hh"

#include <trompeloeil.hpp>

namespace emilpro::mock
{
class MockBinaryParser : public IBinaryParser
{
public:
    MAKE_CONST_MOCK0(GetMachine, Machine(), final);
    MAKE_MOCK1(ForAllSections, void(const std::function<void(std::unique_ptr<ISection>)>&), final);
};

} // namespace emilpro::mock
