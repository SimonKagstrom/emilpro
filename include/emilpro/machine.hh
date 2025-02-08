#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

namespace emilpro
{

enum class Machine : uint8_t
{
    k8086,
    kI386,
    kX86_64,
    kArm,
    kArmThumb, // ARM in thumb mode
    kArm64,
    kMips,
    kPpc,

    kUnknown,
};

const char* MachineToString(Machine machine);
std::optional<Machine> MachineFromString(std::string_view str);

} // namespace emilpro
