#pragma once

#include "emilpro/i_binary_parser.hh"
#include "section.hh"
#include "symbol.hh"

// For libbfd: "error: config.h must be included before this header"
#define PACKAGE         1
#define PACKAGE_VERSION 1

#include <bfd.h>
#include <map>
#include <memory>
#include <unordered_map>
#include <vector>

namespace emilpro
{

class BfdBinaryParser : public IBinaryParser
{
public:
    explicit BfdBinaryParser(std::string_view path);

    virtual ~BfdBinaryParser() final;

    bool Parse();

private:
    Machine GetMachine() const final;
    void ForAllSections(std::function<void(std::unique_ptr<ISection>)> on_section) final;

    std::optional<Section::FileLine> LookupLine(bfd_section* section, bfd_symbol** symTbl, uint64_t offset);
    bool getLineByAddress(uint64_t addr);
    void handleSymbols(long symcount, bfd_symbol** syms, bool dynamic);
    void HandleRelocations(asection* section, bfd_symbol** syms);

private:
    typedef std::map<uint64_t, asection*> BfdSectionByAddress_t;

    Machine m_machine {Machine::kUnknown};
    std::string_view m_path;

    uint8_t* m_rawData;
    size_t m_rawDataSize;
    struct bfd* m_bfd;
    bfd_symbol** m_bfd_syms;
    bfd_symbol** m_dynamic_bfd_syms;
    bfd_symbol** m_synthetic_bfd_syms;
    bfd_symbol* m_rawSynthetic_bfd_syms;

    std::unordered_map<bfd_section*, std::unique_ptr<Section>> m_pending_sections;
    std::unordered_map<bfd_symbol*, Symbol*> m_symbol_map;

    BfdSectionByAddress_t m_sectionByAddress;
};

} // namespace emilpro
