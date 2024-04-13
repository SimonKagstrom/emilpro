#pragma once

#include <cstdint>

namespace emilpro
{

enum class Machine : uint8_t
{
    kX86,
    kAmd64,
    kArm,
    kArm64,
    kMips,
    kPpc,

    kUnknown,
};

}
