#pragma once

#include <cstdint>

namespace emilpro
{

enum class Machine : uint8_t
{
    kX86,
    kAmd64,
    kArm,
    kArmThumb, // ARM in thumb mode
    kArm64,
    kMips,
    kPpc,

    kUnknown,
};

}
