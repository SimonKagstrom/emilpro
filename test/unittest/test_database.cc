#include "emilpro/database.hh"
#include "emilpro/mock/mock_binary_parser.hh"
#include "emilpro/mock/mock_disassembler.hh"
#include "emilpro/mock/mock_instruction.hh"
#include "emilpro/mock/mock_section.hh"
#include "emilpro/mock/mock_symbol.hh"

#include <doctest/doctest.h>
#include <doctest/trompeloeil.hpp>

using namespace emilpro;
using trompeloeil::_;

namespace
{

class Fixture
{
public:
    Fixture()
    {
        binary_parser_up = std::make_unique<mock::MockBinaryParser>();
        disassembler_up = std::make_unique<mock::MockDisassembler>();
        binary_parser = binary_parser_up.get();
        disassembler = disassembler_up.get();

        expectations.push_back(
            NAMED_ALLOW_CALL(*binary_parser, GetMachine()).RETURN(Machine::kX86));
    }

    auto CreateSection() const
    {
        auto section_up = std::make_unique<mock::MockSection>();
        auto section = section_up.get();

        return std::make_pair(std::move(section_up), section);
    }

    auto CreateInstructions(auto& section, auto count)
    {
        std::vector<std::unique_ptr<mock::MockInstruction>> insns;
        std::vector<std::reference_wrapper<IInstruction>> insn_refs;

        for (auto i = 0; i < count; ++i)
        {
            auto insn_up = std::make_unique<mock::MockInstruction>();

            // Some defaults (assume it doesn't reference anything)
            expectations.push_back(NAMED_ALLOW_CALL(*insn_up, Section()).LR_RETURN(section));
            expectations.push_back(NAMED_ALLOW_CALL(*insn_up, RefersTo()).RETURN(std::nullopt));

            insn_refs.push_back(*insn_up);
            insns.push_back(std::move(insn_up));
        }

        return std::make_pair(std::move(insns), insn_refs);
    }

    std::unique_ptr<mock::MockBinaryParser> binary_parser_up;
    std::unique_ptr<mock::MockDisassembler> disassembler_up;
    // Borrowed pointers for the test
    mock::MockBinaryParser* binary_parser;
    mock::MockDisassembler* disassembler;

    Database database;

private:
    std::vector<std::unique_ptr<trompeloeil::expectation>> expectations;
};

} // namespace

TEST_CASE_FIXTURE(Fixture, "the database can resolve references")
{
    GIVEN("a .text section with four instructions and one symbol")
    {
        auto [text_up, text] = CreateSection();
        auto symbol = mock::MockSymbol();
        auto sym_refs = std::vector<std::reference_wrapper<ISymbol>> {symbol};
        auto [insns, insn_refs] = CreateInstructions(*text, 4);

        REQUIRE_CALL(*binary_parser, ForAllSections(_)).LR_SIDE_EFFECT(_1(std::move(text_up)));
        auto r_disassembly = NAMED_REQUIRE_CALL(*text, Disassemble(_));
        REQUIRE_CALL(*text, Symbols()).LR_RETURN(sym_refs);
        auto r_insns = NAMED_REQUIRE_CALL(*text, Instructions()).LR_RETURN(insn_refs);

        // Do the actual parsing
        database.ParseFile(std::move(binary_parser_up), std::move(disassembler_up));

        THEN("the section is disassembled")
        {
            r_disassembly = nullptr;
            r_insns = nullptr;
        }
    }
}
