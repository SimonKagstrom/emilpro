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
    m_size = size;
}

void
Symbol::SetInstructionCount(size_t count)
{
    m_instruction_count = count;
}


std::span<const std::byte>
Symbol::Data() const
{
    return {};
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

size_t
Symbol::InstructionCount() const
{
    return m_instruction_count;
}

std::string_view
Symbol::GetFlags() const
{
    return m_flags;
}

std::string_view
Symbol::GetName() const
{
    return m_name;
}

std::string_view
Symbol::GetDemangledName() const
{
    return m_demanged_name;
}

void
Symbol::AddRelocation(const ISection& src_section, uint64_t offset)
{
    m_relocations.push_back(src_section);
    auto start_addr = m_relocations.back().get().StartAddress();
    fmt::print(
        "SYM {} add reloc from sect {:x}. Offset {}\n", GetDemangledName(), start_addr, offset);
}
