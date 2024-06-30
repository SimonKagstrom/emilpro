#include "emilpro/i_section.hh"
#include "emilpro/i_symbol.hh"

#include <atomic>
#include <mutex>
#include <semaphore>
#include <vector>

#pragma once

namespace emilpro
{

class Symbol : public ISymbol
{
public:
    Symbol(const ISection& section, uint64_t offset, std::string_view flags, std::string_view name);

    void SetSize(size_t size);

    void AddRelocation(const ISection& src_section, uint64_t offset);

    std::span<const std::byte> Data() const final;
    const ISection& Section() const final;
    uint64_t Offset() const final;
    size_t Size() const final;
    const std::string& Flags() const final;
    const std::string& Name() const final;
    const std::string& DemangledName() const final;
    std::span<const std::reference_wrapper<IInstruction>> Instructions() const final;
    std::span<const IInstruction::Referer> ReferredBy() const final;
    std::span<const IInstruction::Referer> RefersTo() const final;

    void WaitForCommit() final;

    // Currently processed instructions (before commit)
    std::vector<std::reference_wrapper<IInstruction>>& InstructionsStore();

    void SetInstructions(std::span<const std::reference_wrapper<IInstruction>> instructions);
    void AddReferredBy(std::span<const IInstruction::Referer> referers);
    void AddRefersTo(const IInstruction::Referer& referer);

    // Called when all referrers/referred by are done
    void Commit();

private:
    const ISection& m_section;
    const uint64_t m_offset;
    size_t m_size {0};
    std::string m_flags;
    std::string m_name;
    std::string m_demanged_name;
    std::span<const std::byte> m_data;

    std::vector<std::reference_wrapper<const ISection>> m_relocations;
    std::vector<std::reference_wrapper<IInstruction>> m_instructions_store;
    std::span<const std::reference_wrapper<IInstruction>> m_instructions;

    std::span<const IInstruction::Referer> m_referred_by;
    std::span<const IInstruction::Referer> m_refers_to;

    std::vector<IInstruction::Referer> m_referred_by_store;
    std::vector<IInstruction::Referer> m_refers_to_store;

    mutable std::mutex m_mutex;

    std::atomic_bool m_committed {false};
    std::binary_semaphore m_commit_semaphore {0};
};

} // namespace emilpro
