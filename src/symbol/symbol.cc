#include "symbol.hh"

#include <fmt/format.h>
#include <libiberty/demangle.h>

using namespace emilpro;

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

std::span<const std::byte>
Symbol::Data() const
{
    return {};
}

const ISection&
Symbol::GetSection()
{
    return m_section;
}

uint64_t
Symbol::GetOffset() const
{
    return m_offset;
}

size_t
Symbol::Size() const
{
    return m_size;
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
    fmt::print("SYM {} add reloc from sect {:x}. Offset {}\n", GetDemangledName(), start_addr, offset);
}
