#include "capstone_disassembler.hh"

#include <array>
#include <fmt/format.h>
#include <ranges>
#include <etl/vector.h>

using namespace emilpro;

constexpr auto kMachineMap = std::array {
    std::pair {Machine::kX86, cs_arch::CS_ARCH_X86},
    std::pair {Machine::kArm, cs_arch::CS_ARCH_ARM},
    std::pair {Machine::kArm64, cs_arch::CS_ARCH_ARM64},
    std::pair {Machine::kMips, cs_arch::CS_ARCH_MIPS},
    std::pair {Machine::kPpc, cs_arch::CS_ARCH_PPC},
};

constexpr auto kArmCallMap = std::array {
    arm_insn::ARM_INS_BL,
};

namespace
{

class CapstoneInstruction : public IInstruction
{
public:
    CapstoneInstruction(cs_arch arch, std::span<const std::byte> data, const cs_insn* insn)
        : data_(data.subspan(0, insn->size))
        , encoding_(fmt::format("{:16s} {}", insn->mnemonic, insn->op_str))
        , offset_(insn->address)
    {
        switch (arch)
        {
        case cs_arch::CS_ARCH_ARM:
            ProcessArm(insn);
            break;
        case cs_arch::CS_ARCH_X86:
            ProcessArm(insn);
            break;
        default:
            break;
        }
    }

private:
    void ProcessArm(const cs_insn* insn)
    {
        if (insn->id == arm_insn::ARM_INS_BL)
        {
            refers_to_.push_back(insn->detail->arm.operands[0].imm);
        }
        else if (IsJump(insn))
        {
            refers_to_.push_back(insn->detail->arm.operands[0].imm);
        }
    }

    void ProcessX86(const cs_insn* insn)
    {
        if (insn->id == x86_insn::X86_INS_CALL)
        {
            refers_to_.push_back(insn->detail->x86.operands[0].imm);
        }
    }

    bool IsJump(const cs_insn *insn) const
    {
        for (auto i = 0u; i < insn->detail->groups_count; i++)
        {
            if (insn->detail->groups[i] == cs_group_type::CS_GRP_JUMP)
            {
                return true;
            }
        }

        return false;
    }



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
        return refers_to_;
    }

    std::span<std::string_view> GetUsedRegisters() const final
    {
        return {};
    }


    std::span<const std::byte> data_;
    // I don't think there are instructions with more than one immediate reference, but just in case
    etl::vector<uint64_t, 2> refers_to_;
    const std::string encoding_;
    const uint32_t offset_;
};

} // namespace


CapstoneDisassembler::CapstoneDisassembler(cs_arch arch)
    : m_arch(arch)
{
    cs_open(m_arch, CS_MODE_LITTLE_ENDIAN, &m_handle);

    size_t option = CS_OPT_ON;

    cs_option(m_handle, CS_OPT_DETAIL, option);
    if (m_arch == cs_arch::CS_ARCH_X86)
    {
        option = CS_OPT_SYNTAX_ATT;
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

    printf("Disassembling at 0x%08llx\n", start_address);
    auto n = cs_disasm(m_handle,
                       reinterpret_cast<const uint8_t*>(data.data()),
                       data.size(),
                       start_address,
                       0,
                       &insns);
    for (auto i = 0; i < n; i++)
    {
        auto p = &insns[i];
        on_instruction(std::make_unique<CapstoneInstruction>(m_arch, data, p));
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
