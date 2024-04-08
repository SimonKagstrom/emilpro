#pragma once

#include <memory>

namespace emilpro
{

class IDisassembler
{
public:
    virtual ~IDisassembler() = default;

    static std::unique_ptr<IDisassembler> Create();
};

} // namespace emilpro
