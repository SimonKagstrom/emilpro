#include "capstone_disassembler.hh"

#include <array>
#include <fmt/format.h>
#include <ranges>

using namespace emilpro;

constexpr auto kMachineMap = std::array {
    std::pair {Machine::kX86, cs_arch::CS_ARCH_X86},
    std::pair {Machine::kArm, cs_arch::CS_ARCH_ARM},
    std::pair {Machine::kArm64, cs_arch::CS_ARCH_ARM64},
    std::pair {Machine::kMips, cs_arch::CS_ARCH_MIPS},
    std::pair {Machine::kPpc, cs_arch::CS_ARCH_PPC},
};

namespace
{

class CapstoneInstruction : public IInstruction
{
public:
    CapstoneInstruction(std::span<const std::byte> data, cs_insn* insn)
        : data_(data.subspan(0, insn->size))
        , encoding_(fmt::format("{:16s} {}", insn->mnemonic, insn->op_str))
        , offset_(insn->address)
    {
    }

private:
    uint32_t GetOffset() const final
    {
        return offset_;
    }

    std::string_view AsString() const final
    {
        return encoding_;
    }

    std::span<const uint64_t> GetReferredBy() const final
    {
        return {};
    }

    std::span<const uint64_t> GetRefersTo() const final
    {
        return {};
    }

    std::span<std::string_view> GetUsedRegisters() const final
    {
        return {};
    }


    std::span<const std::byte> data_;
    const std::string encoding_;
    const uint32_t offset_;
};

} // namespace


CapstoneDisassembler::CapstoneDisassembler(cs_arch machine)
{
    cs_open(machine, CS_MODE_LITTLE_ENDIAN, &m_handle);

    if (machine == cs_arch::CS_ARCH_X86)
    {
        size_t option = CS_OPT_SYNTAX_ATT;
        cs_option(m_handle, CS_OPT_SYNTAX, option);
    }
}

CapstoneDisassembler::~CapstoneDisassembler()
{
    cs_close(&m_handle);
}

void
CapstoneDisassembler::Disassemble(std::span<const std::byte> data,
                                  uint64_t start_address,
                                  std::function<void(std::unique_ptr<IInstruction>)> on_instruction)
{
    cs_insn* insns = nullptr;

    auto n = cs_disasm(m_handle,
                       reinterpret_cast<const uint8_t*>(data.data()),
                       data.size(),
                       start_address,
                       0,
                       &insns);
    for (auto i = 0; i < n; i++)
    {
        auto p = &insns[i];
        on_instruction(std::make_unique<CapstoneInstruction>(data, p));
    }
}


std::unique_ptr<CapstoneDisassembler>
CapstoneDisassembler::Create(Machine machine)
{
    auto it = std::ranges::find_if(kMachineMap,
                                   [machine](const auto& pair) { return pair.first == machine; });

    if (it == kMachineMap.end())
    {
        return nullptr;
    }

    auto p = new CapstoneDisassembler(it->second);

    return std::unique_ptr<CapstoneDisassembler>(p);
}

std::unique_ptr<IDisassembler>
IDisassembler::CreateFromArchitecture(Machine machine)
{
    return CapstoneDisassembler::Create(machine);
}
