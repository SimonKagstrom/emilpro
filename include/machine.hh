#pragma once

#include <cstdint>

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
