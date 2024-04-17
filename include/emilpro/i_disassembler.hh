#pragma once

#include "i_instruction.hh"
#include "i_section.hh"
#include "machine.hh"

#include <functional>
#include <memory>

namespace emilpro
{

class IDisassembler
{
public:
    virtual ~IDisassembler() = default;

    virtual void Disassemble(const ISection& section,
                             uint64_t start_address,
                             std::span<const std::byte> data,
                             std::function<void(std::unique_ptr<IInstruction>)> on_instruction) = 0;

    static std::unique_ptr<IDisassembler> CreateFromArchitecture(Machine machine);
};

} // namespace emilpro
