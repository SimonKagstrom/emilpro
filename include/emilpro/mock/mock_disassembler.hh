#include "../i_disassembler.hh"

#include <trompeloeil.hpp>

namespace emilpro::mock
{
class MockDisassembler : public IDisassembler
{
public:
    MAKE_MOCK5(Disassemble,
               void(const ISection& section,
                    const ISymbol* symbol,
                    uint64_t start_address,
                    std::span<const std::byte> data,
                    std::function<void(std::unique_ptr<IInstruction>)> on_instruction),
               final);
};

} // namespace emilpro::mock