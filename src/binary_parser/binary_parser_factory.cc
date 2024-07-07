#include "bfd_binary_parser.hh"
#include "emilpro/i_binary_parser.hh"
#include "emilpro/machine.hh"

#include <array>
#include <utility>

using namespace emilpro;

constexpr auto kMachineTable = std::array {
    std::pair {Machine::kX86, "Intel x86"},
    std::pair {Machine::kAmd64, "AMD64"},
    std::pair {Machine::kArm, "ARM"},
    std::pair {Machine::kArmThumb, "ARM (thumb mode)"},
    std::pair {Machine::kArm64, "ARM64"},
    std::pair {Machine::kMips, "MIPS"},
    std::pair {Machine::kPpc, "PowerPC"},
};
static_assert(kMachineTable.size() == static_cast<size_t>(Machine::kUnknown));

// Put them here for now, although not a good place
const char*
emilpro::MachineToString(Machine machine)
{
    if (auto it = std::ranges::find_if(
            kMachineTable, [machine](const auto& pair) { return pair.first == machine; });
        it != kMachineTable.end())
    {
        return it->second;
    }

    return "";
}

std::optional<Machine>
emilpro::MachineFromString(std::string_view str)
{
    if (auto it = std::ranges::find_if(kMachineTable,
                                       [str](const auto& pair) { return pair.second == str; });
        it != kMachineTable.end())
    {
        return it->first;
    }

    return std::nullopt;
}


std::unique_ptr<IBinaryParser>
IBinaryParser::FromFile(std::string_view path, std::optional<Machine> machine_hint)
{
    auto out = std::make_unique<BfdBinaryParser>(path, machine_hint);

    if (!out->Parse())
    {
        return nullptr;
    }

    return out;
}
