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

    auto CreateSection(auto start_address, auto size)
    {
        auto section_up = std::make_unique<mock::MockSection>();
        auto section = section_up.get();

        expectations.push_back(NAMED_ALLOW_CALL(*section_up, StartAddress()).RETURN(start_address));
        expectations.push_back(NAMED_ALLOW_CALL(*section_up, Size()).RETURN(size));
        expectations.push_back(NAMED_ALLOW_CALL(*section_up, ContainsAddress(_))
                                   .RETURN(_1 >= start_address && _1 < start_address + size));

        return std::pair {std::move(section_up), section};
    }

    auto CreateInstructions(auto& section, auto count)
    {
        std::vector<std::unique_ptr<mock::MockInstruction>> insns;
        std::vector<std::reference_wrapper<IInstruction>> insn_refs;

        for (auto i = 0; i < count; ++i)
        {
            auto insn_up = std::make_unique<mock::MockInstruction>();
            auto insn = insn_up.get();

            // Some defaults (assume it doesn't reference anything)
            expectations.push_back(NAMED_ALLOW_CALL(*insn_up, Section()).LR_RETURN(section));
            expectations.push_back(NAMED_ALLOW_CALL(*insn_up, RefersTo()).RETURN(std::nullopt));
            expectations.push_back(NAMED_ALLOW_CALL(*insn_up, Offset()).RETURN(i));

            expectations.push_back(NAMED_ALLOW_CALL(section, InstructionAt(i)).RETURN(insn));

            insn_refs.push_back(*insn_up);
            insns.push_back(std::move(insn_up));
        }

        return std::pair {std::make_pair(std::move(insns), insn_refs)};
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
    GIVEN("a .text section with a few instructions and one symbol")
    {
        auto section = CreateSection(0x1000, 5);
        auto text_up = std::move(section.first);
        auto text = section.second;
        auto symbol = mock::MockSymbol();
        auto sym_refs = std::vector<std::reference_wrapper<ISymbol>> {symbol};

        auto insn_pair = CreateInstructions(*text, 5);
        auto insns = std::move(insn_pair.first);
        auto insn_refs = std::move(insn_pair.second);

        /*
         * 0  sym: add $1, %eax
         * 1       jmp 3         // Forward branch
         * 2       jmp 3
         * 3       nop
         * 4       jmp 0         // Backward branch, and has two references
         */
        using R = IInstruction::Referer;
        REQUIRE_CALL(*insns[1], RefersTo()).RETURN(R {text, 3, nullptr});
        REQUIRE_CALL(*insns[2], RefersTo()).RETURN(R {text, 3, nullptr});
        REQUIRE_CALL(*insns[4], RefersTo()).LR_RETURN(R {text, 0, &symbol});

        auto r_referred0 =
            NAMED_REQUIRE_CALL(*insns[0], AddReferredBy(_, 4, nullptr)).LR_WITH(&_1 == text);
        auto r_referred1 =
            NAMED_REQUIRE_CALL(*insns[3], AddReferredBy(_, 1, nullptr)).LR_WITH(&_1 == text);
        auto r_referred2 =
            NAMED_REQUIRE_CALL(*insns[3], AddReferredBy(_, 2, nullptr)).LR_WITH(&_1 == text);

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
        AND_THEN("the cross-references are calculated")
        {
            r_referred0 = nullptr;
            r_referred1 = nullptr;
            r_referred2 = nullptr;
        }
    }
}
