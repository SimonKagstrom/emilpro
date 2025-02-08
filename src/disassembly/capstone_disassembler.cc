#include "capstone_disassembler.hh"

#include <array>
#include <cassert>
#include <etl/vector.h>
#include <fmt/format.h>
#include <mutex>
#include <ranges>

using namespace emilpro;

constexpr auto kMachineMap = std::array {
    std::pair {Machine::k8086, cs_arch::CS_ARCH_X86},
    std::pair {Machine::kI386, cs_arch::CS_ARCH_X86},
    std::pair {Machine::kX86_64, cs_arch::CS_ARCH_X86},
    std::pair {Machine::kArm, cs_arch::CS_ARCH_ARM},
    std::pair {Machine::kArmThumb, cs_arch::CS_ARCH_ARM},
    std::pair {Machine::kArm64, cs_arch::CS_ARCH_ARM64},
    std::pair {Machine::kMips, cs_arch::CS_ARCH_MIPS},
    std::pair {Machine::kPpc, cs_arch::CS_ARCH_PPC},
};
static_assert(kMachineMap.size() == std::to_underlying(Machine::kUnknown));

namespace
{

class CapstoneInstruction : public IInstruction
{
public:
    CapstoneInstruction(csh handle,
                        const ISection& section,
                        const ISymbol* symbol,
                        cs_arch arch,
                        uint64_t offset,
                        std::span<const std::byte> data,
                        const cs_insn* insn)
        : m_handle(handle)
        , m_section(section)
        , m_symbol(symbol)
        , m_data(data.subspan(0, std::min(static_cast<size_t>(insn->size), data.size())))
        , m_type(DetermineType(insn))
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
        case cs_arch::CS_ARCH_ARM64:
            ProcessArm64(insn);
            break;
        case cs_arch::CS_ARCH_MIPS:
            ProcessMips(insn);
            break;
        default:
            break;
        }

        // Indirect registers
        for (auto i = 0u; i < insn->detail->regs_read_count; i++)
        {
            auto name = cs_reg_name(m_handle, insn->detail->regs_read[i]);

            if (name)
            {
                m_used_registers.emplace_back(name);
            }
        }
        for (auto i = 0u; i < insn->detail->regs_write_count; i++)
        {
            auto name = cs_reg_name(m_handle, insn->detail->regs_write[i]);

            if (name)
            {
                m_used_registers.emplace_back(name);
            }
        }
    }

private:
    IInstruction::InstructionType DetermineType(const cs_insn* insn) const
    {
        for (auto i = 0u; i < insn->detail->groups_count; i++)
        {
            if (insn->detail->groups[i] == cs_group_type::CS_GRP_CALL)
            {
                return IInstruction::InstructionType::kCall;
            }
            else if (insn->detail->groups[i] == cs_group_type::CS_GRP_JUMP ||
                     insn->detail->groups[i] == cs_group_type::CS_GRP_BRANCH_RELATIVE)
            {
                return IInstruction::InstructionType::kBranch;
            }
        }

        return IInstruction::InstructionType::kOther;
    }

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

        for (auto i = 0u; i < insn->detail->arm.op_count; i++)
        {
            const auto& op = insn->detail->arm.operands[i];
            if (op.type == ARM_OP_REG)
            {
                m_used_registers.emplace_back(cs_reg_name(m_handle, op.reg));
            }
            else if (op.type == ARM_OP_MEM)
            {
                if (op.mem.base != ARM_REG_INVALID)
                {
                    m_used_registers.emplace_back(cs_reg_name(m_handle, op.mem.base));
                }
                if (op.mem.index != ARM_REG_INVALID)
                {
                    m_used_registers.emplace_back(cs_reg_name(m_handle, op.mem.index));
                }
            }
        }
    }

    void ProcessArm64(const cs_insn* insn)
    {
        if (insn->id == arm64_insn::ARM64_INS_BL)
        {
            m_refers_to = IInstruction::Referer {
                nullptr, static_cast<uint64_t>(insn->detail->arm64.operands[0].imm), nullptr};
        }
        else if (IsJump(insn))
        {
            for (auto i = 0u; i < insn->detail->arm64.op_count; i++)
            {
                const auto& op = insn->detail->arm64.operands[i];
                if (op.type == ARM64_OP_IMM)
                {
                    // Only consider the last immediate as an address (e.g., "tbnz     w8, #0, #0xbe4")
                    m_refers_to =
                        IInstruction::Referer {&m_section, static_cast<uint64_t>(op.imm), nullptr};
                }
            }
        }

        for (auto i = 0u; i < insn->detail->arm64.op_count; i++)
        {
            const auto& op = insn->detail->arm64.operands[i];
            if (op.type == ARM64_OP_REG)
            {
                m_used_registers.emplace_back(cs_reg_name(m_handle, op.reg));
            }
            else if (op.type == ARM64_OP_MEM)
            {
                if (op.mem.base != ARM64_REG_INVALID)
                {
                    m_used_registers.emplace_back(cs_reg_name(m_handle, op.mem.base));
                }
                if (op.mem.index != ARM64_REG_INVALID)
                {
                    m_used_registers.emplace_back(cs_reg_name(m_handle, op.mem.index));
                }
            }
        }
    }

    void ProcessX86(const cs_insn* insn)
    {
        auto upper_section_address = m_section.StartAddress() & 0xffffffff00000000ull;

        if (insn->id == x86_insn::X86_INS_CALL)
        {
            m_refers_to = IInstruction::Referer {
                nullptr,
                upper_section_address + static_cast<uint64_t>(insn->detail->x86.operands[0].imm),
                nullptr};
        }
        else if (IsJump(insn) && insn->detail->x86.op_count > 0 &&
                 insn->detail->x86.operands[0].type == X86_OP_IMM)
        {
            m_refers_to = IInstruction::Referer {
                &m_section,
                upper_section_address + static_cast<uint64_t>(insn->detail->x86.operands[0].imm),
                nullptr};
        }

        for (auto i = 0u; i < insn->detail->x86.op_count; i++)
        {
            const auto& op = insn->detail->x86.operands[i];
            if (op.type == X86_OP_REG)
            {
                m_used_registers.emplace_back(cs_reg_name(m_handle, op.reg));
            }
            if (op.type == X86_OP_MEM)
            {
                if (op.mem.base != X86_REG_INVALID)
                {
                    m_used_registers.emplace_back(cs_reg_name(m_handle, op.mem.base));
                }
                if (op.mem.index != X86_REG_INVALID)
                {
                    m_used_registers.emplace_back(cs_reg_name(m_handle, op.mem.index));
                }
            }
        }
    }

    void ProcessMips(const cs_insn* insn)
    {
        if (insn->id == mips_insn::MIPS_INS_JAL || insn->id == mips_insn::MIPS_INS_BAL)
        {
            m_refers_to = IInstruction::Referer {
                nullptr, static_cast<uint64_t>(insn->detail->mips.operands[0].imm), nullptr};
        }
        else if (IsJump(insn) && insn->detail->mips.op_count > 0 &&
                 insn->detail->mips.operands[0].type == MIPS_OP_IMM)
        {
            m_refers_to = IInstruction::Referer {
                &m_section, static_cast<uint64_t>(insn->detail->mips.operands[0].imm), nullptr};
        }

        for (auto i = 0u; i < insn->detail->mips.op_count; i++)
        {
            const auto& op = insn->detail->mips.operands[i];
            if (op.type == MIPS_OP_REG)
            {
                m_used_registers.emplace_back(cs_reg_name(m_handle, op.reg));
            }
            if (op.type == MIPS_OP_MEM)
            {
                if (op.mem.base != MIPS_REG_INVALID)
                {
                    m_used_registers.emplace_back(cs_reg_name(m_handle, op.mem.base));
                }
            }
        }
    }


    bool IsJump(const cs_insn* insn) const
    {
        return m_type == IInstruction::InstructionType::kBranch;
    }

    std::span<const std::byte> Data() const final
    {
        return m_data;
    }

    InstructionType Type() const final
    {
        return m_type;
    }

    uint32_t Size() const final
    {
        return m_data.size();
    }

    uint64_t Offset() const final
    {
        return m_offset;
    }

    std::string_view AsString() const final
    {
        return m_encoding;
    }

    std::span<const Referer> ReferredBy() const final
    {
        std::scoped_lock lock(m_mutex);

        return m_referred_by;
    }

    std::optional<Referer> RefersTo() const final
    {
        std::scoped_lock lock(m_mutex);

        return m_refers_to;
    }

    void SetRefersTo(const ISection& section, uint64_t offset, const ISymbol* symbol) final
    {
        m_refers_to_store = IInstruction::Referer {&section, offset, symbol};
    }

    void AddReferredBy(const ISection& section, uint64_t offset, const ISymbol* symbol) final
    {
        m_referred_by_store.push_back({&section, offset, symbol});
    }

    void Commit() final
    {
        std::scoped_lock lock(m_mutex);

        if (!m_referred_by_store.empty())
        {
            m_referred_by = m_referred_by_store;
        }
        if (m_refers_to_store)
        {
            m_refers_to = m_refers_to_store;
        }
        m_source_file = m_source_file_store;
        m_source_line = m_source_line_store;
    }

    std::span<const std::string> UsedRegisters() const final
    {
        return m_used_registers;
    }

    std::optional<std::pair<std::string_view, uint32_t>> GetSourceLocation() const final
    {
        std::scoped_lock lock(m_mutex);

        std::optional<std::pair<std::string_view, uint32_t>> out = std::nullopt;

        if (m_source_file && m_source_line)
        {
            out = {*m_source_file, *m_source_line};
        }

        return out;
    }

    const ISection& Section() const final
    {
        return m_section;
    }

    const ISymbol* Symbol() const final
    {
        return m_symbol;
    }

    void SetSourceLocation(std::string_view file, uint32_t line) final
    {
        m_source_file_store = file;
        m_source_line_store = line;
    }


    csh m_handle;
    const ISection& m_section;
    const ISymbol* m_symbol;
    std::span<const std::byte> m_data;
    const IInstruction::InstructionType m_type;
    std::optional<IInstruction::Referer> m_refers_to;
    std::span<const IInstruction::Referer> m_referred_by;

    std::optional<IInstruction::Referer> m_refers_to_store;
    std::vector<IInstruction::Referer> m_referred_by_store;
    const std::string m_encoding;
    const uint64_t m_offset;

    std::optional<std::string> m_source_file;
    std::optional<uint32_t> m_source_line;
    std::optional<std::string> m_source_file_store;
    std::optional<uint32_t> m_source_line_store;

    std::vector<std::string> m_used_registers;

    mutable std::mutex m_mutex;
};

} // namespace


CapstoneDisassembler::CapstoneDisassembler(cs_arch arch, cs_mode mode)
    : m_arch(arch)
{
    cs_open(m_arch, mode, &m_handle);

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
                                  const ISymbol* symbol,
                                  uint64_t start_address,
                                  std::span<const std::byte> data,
                                  std::function<void(std::unique_ptr<IInstruction>)> on_instruction)
{
    auto insn = cs_malloc(m_handle);

    auto code = reinterpret_cast<const uint8_t*>(data.data());
    auto size = data.size();
    auto address = start_address;
    auto cur_address = address;

    auto offset = 0;
    while (cs_disasm_iter(m_handle, &code, &size, &address, insn))
    {
        on_instruction(std::make_unique<CapstoneInstruction>(
            m_handle, section, symbol, m_arch, cur_address, data.subspan(offset), insn));
        cur_address = address;
        offset += insn->size;
    }

    cs_free(insn, 1);
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
    unsigned int mode = CS_MODE_LITTLE_ENDIAN;

    switch (it->first)
    {
    case Machine::k8086:
        mode |= CS_MODE_16;
        break;
    case Machine::kI386:
        mode |= CS_MODE_32;
        break;
    case Machine::kX86_64:
        mode |= CS_MODE_64;
        break;
    case Machine::kArmThumb:
        mode |= CS_MODE_THUMB;
        break;

    default:
        break;
    }

    auto p = new CapstoneDisassembler(it->second, static_cast<cs_mode>(mode));

    return std::unique_ptr<CapstoneDisassembler>(p);
}

std::unique_ptr<IDisassembler>
IDisassembler::CreateFromArchitecture(Machine machine)
{
    return CapstoneDisassembler::Create(machine);
}
