#include "../i_section.hh"

#include <trompeloeil.hpp>

namespace emilpro::mock
{
class MockSection : public ISection
{
public:
    MAKE_CONST_MOCK0(Data, (std::span<const std::byte>)(), final);
    MAKE_CONST_MOCK0(StartAddress, uint64_t(), final);
    MAKE_CONST_MOCK0(Size, size_t(), final);
    MAKE_CONST_MOCK0(GetType, Type(), final);
    MAKE_CONST_MOCK0(Flags, const std::string&(), final);
    MAKE_CONST_MOCK0(Name, const std::string&(), final);
    MAKE_CONST_MOCK0(Instructions,
                     (std::span<const std::reference_wrapper<IInstruction>>)(),
                     final);
    MAKE_CONST_MOCK0(Symbols, (std::span<const std::reference_wrapper<ISymbol>>)(), final);
    MAKE_CONST_MOCK1(ContainsAddress, bool(uint64_t), final);
    MAKE_MOCK1(Disassemble, void(IDisassembler&), final);
    MAKE_CONST_MOCK1(InstructionAt, IInstruction*(uint64_t), final);
};

} // namespace emilpro::mock
