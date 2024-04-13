#pragma once

#include "emilpro/i_disassembler.hh"

#include <capstone/capstone.h>

namespace emilpro
{

class CapstoneDisassembler : public IDisassembler
{
public:
    static std::unique_ptr<CapstoneDisassembler> Create(Machine machine);

    ~CapstoneDisassembler() final;

private:
    void Disassemble(std::span<const std::byte> data,
                     uint64_t start_address,
                     std::function<void(std::unique_ptr<IInstruction>)> on_instruction) final;

    CapstoneDisassembler(cs_arch machine);
    csh m_handle;
};

} // namespace emilpro