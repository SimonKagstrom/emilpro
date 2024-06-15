#include "symbol.hh"

#include <fmt/format.h>

using namespace emilpro;

// From libiberty. Including demangle.h conflicts with string.h though
#define DMGL_PARAMS  (1 << 0) /* Include function args */
#define DMGL_ANSI    (1 << 1) /* Include const, volatile, etc */
#define DMGL_VERBOSE (1 << 3) /* Include implementation details.  */

extern "C" char* cplus_demangle(const char* mangled, int options);


Symbol::Symbol(const ISection& section,
               uint64_t offset,
               std::string_view flags,
               std::string_view name)
    : m_section(section)
    , m_offset(offset)
    , m_flags(flags)
    , m_name(name)
    , m_data(section.Data().subspan(offset))
{
    // Use what c++filt uses...
    int demangle_flags = DMGL_PARAMS | DMGL_ANSI | DMGL_VERBOSE;

    auto demangled = cplus_demangle(m_name.c_str(), demangle_flags);

    if (demangled)
    {
        m_demanged_name = demangled;
    }
    else
    {
        m_demanged_name = m_name;
    }

    free(demangled);
}

void
Symbol::SetSize(size_t size)
{
    size_t max = std::distance(m_section.Data().begin() + m_offset, m_section.Data().end());

    m_size = std::min(size, max);
    m_data = m_section.Data().subspan(m_offset, m_size);
}


std::span<const std::byte>
Symbol::Data() const
{
    return m_data;
}

const ISection&
Symbol::Section() const
{
    return m_section;
}

uint64_t
Symbol::Offset() const
{
    return m_offset;
}

size_t
Symbol::Size() const
{
    return m_size;
}

const std::string&
Symbol::Flags() const
{
    return m_flags;
}

const std::string&
Symbol::Name() const
{
    return m_name;
}

const std::string&
Symbol::DemangledName() const
{
    return m_demanged_name;
}

void
Symbol::AddRelocation(const ISection& src_section, uint64_t offset)
{
    m_relocations.emplace_back(src_section);
}

std::span<const std::reference_wrapper<IInstruction>>
Symbol::Instructions() const
{
    return m_instructions;
}

std::span<const IInstruction::Referer>
Symbol::ReferredBy() const
{
    return m_referred_by;
}


std::span<const IInstruction::Referer>
Symbol::RefersTo() const
{
    return m_refers_to;
}

void
Symbol::AddReferredBy(const IInstruction::Referer& referer)
{
    m_referred_by_store.emplace_back(referer);
}

void
Symbol::AddRefersTo(const IInstruction::Referer& referer)
{
    m_refers_to_store.emplace_back(referer);
}

void
Symbol::Commit()
{
    m_refers_to = m_refers_to_store;
    m_referred_by = m_referred_by_store;
}


void
Symbol::SetInstructions(std::span<const std::reference_wrapper<IInstruction>> instructions)
{
    std::ranges::copy(instructions, std::back_inserter(m_instructions));
}
