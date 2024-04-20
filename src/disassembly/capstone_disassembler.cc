#include "capstone_disassembler.hh"

#include <array>
#include <cassert>
#include <etl/vector.h>
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

constexpr auto kArmCallMap = std::array {
    arm_insn::ARM_INS_BL,
};

namespace
{

class CapstoneInstruction : public IInstruction
{
public:
    CapstoneInstruction(const ISection& section,
                        cs_arch arch,
                        uint64_t offset,
                        std::span<const std::byte> data,
                        const cs_insn* insn)
        : m_section(section)
        , m_data(data.subspan(0, insn->size))
        , m_encoding(fmt::format("{:8s} {}", insn->mnemonic, insn->op_str))
        , m_offset(offset)
    {
        switch (arch)
        {
        case cs_arch::CS_ARCH_ARM:
            ProcessArm(insn);
            break;
        case cs_arch::CS_ARCH_X86:
            ProcessX86(insn);
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
            m_refers_to = IInstruction::Referer {
                nullptr, static_cast<uint64_t>(insn->detail->arm.operands[0].imm), nullptr};
        }
        else if (IsJump(insn) && insn->detail->arm.op_count > 0 &&
                 insn->detail->arm.operands[0].type == ARM_OP_IMM)
        {
            m_refers_to = IInstruction::Referer {
                &m_section, static_cast<uint64_t>(insn->detail->arm.operands[0].imm), nullptr};
        }
    }

    void ProcessX86(const cs_insn* insn)
    {
        if (insn->id == x86_insn::X86_INS_CALL)
        {
            m_refers_to = IInstruction::Referer {
                nullptr,
                static_cast<uint64_t>(insn->address + insn->detail->arm.operands[0].imm),
                nullptr};
        }
        else if (IsJump(insn) && insn->detail->x86.op_count > 0 &&
                 insn->detail->x86.operands[0].type == X86_OP_IMM)
        {
            m_refers_to = IInstruction::Referer {
                &m_section, static_cast<uint64_t>(insn->detail->x86.operands[0].imm), nullptr};
        }
    }

    bool IsJump(const cs_insn* insn) const
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

    std::span<const std::byte> Data() const final
    {
        return m_data;
    }

    uint32_t Size() const final
    {
        return m_data.size();
    }

    uint32_t Offset() const final
    {
        return m_offset;
    }

    std::string_view AsString() const final
    {
        return m_encoding;
    }

    std::span<const Referer> ReferredBy() const final
    {
        return m_referred_by;
    }

    std::optional<Referer> RefersTo() const final
    {
        return m_refers_to;
    }

    void SetRefersTo(const ISection& section, uint64_t offset, const ISymbol* symbol) final
    {
        m_refers_to = IInstruction::Referer {&section, offset, symbol};
    }

    void AddReferredBy(const ISection& section, uint64_t offset, const ISymbol* symbol) final
    {
        m_referred_by.push_back({&section, offset, symbol});
    }


    std::span<std::string_view> GetUsedRegisters() const final
    {
        return {};
    }

    std::optional<std::pair<std::string_view, uint32_t>> GetSourceLocation() const final
    {
        std::optional<std::pair<std::string_view, uint32_t>> out = std::nullopt;

        if (source_file_ && source_line_)
        {
            out = {*source_file_, *source_line_};
        }

        return out;
    }

    const ISection& Section() const final
    {
        return m_section;
    }

    void SetSourceLocation(std::string_view file, uint32_t line) final
    {
        source_file_ = file;
        source_line_ = line;
    }


    const ISection& m_section;
    std::span<const std::byte> m_data;
    std::optional<IInstruction::Referer> m_refers_to;
    std::vector<IInstruction::Referer> m_referred_by;
    const std::string m_encoding;
    const uint32_t m_offset;

    std::optional<std::string> source_file_;
    std::optional<uint32_t> source_line_;
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
CapstoneDisassembler::Disassemble(const ISection& section,
                                  uint64_t start_address,
                                  std::span<const std::byte> data,
                                  std::function<void(std::unique_ptr<IInstruction>)> on_instruction)
{
    cs_insn* insns = nullptr;

    auto n = cs_disasm(m_handle,
                       reinterpret_cast<const uint8_t*>(data.data()),
                       data.size(),
                       start_address,
                       0,
                       &insns);

    uint64_t offset = start_address - section.StartAddress();
    for (auto i = 0; i < n; i++)
    {
        auto p = &insns[i];
        on_instruction(std::make_unique<CapstoneInstruction>(section, m_arch, offset, data, p));
        offset += p->size;
        data = data.subspan(p->size);
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
