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
    void Disassemble(const ISection& section,
                     std::function<void(std::unique_ptr<IInstruction>)> on_instruction) final;

    CapstoneDisassembler(cs_arch arch);
    csh m_handle;
    cs_arch m_arch;
};

} // namespace emilpro