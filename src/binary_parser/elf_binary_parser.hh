#include "emilpro/i_binary_parser.hh"

#define PACKAGE         1
#define PACKAGE_VERSION 1

#include <bfd.h>
#include <map>
namespace emilpro
{

class ElfBinaryParser : public IBinaryParser
{
public:
    explicit ElfBinaryParser(std::string_view path);

    virtual ~ElfBinaryParser() final;

    bool Parse();

private:
    Machine GetMachine() const final;
    void ForAllSections(std::function<void(std::unique_ptr<ISection>)> on_section) final;

    bool lookupLine(bfd_section* section, bfd_symbol** symTbl, uint64_t addr);
    bool getLineByAddress(uint64_t addr);
	void handleSymbols(long symcount, bfd_symbol **syms, bool dynamic);

private:
    typedef std::map<asection*, void*> BfdSectionContents_t;
    typedef std::map<uint64_t, asection*> BfdSectionByAddress_t;

    std::string_view m_path;

    uint8_t* m_rawData;
    size_t m_rawDataSize;
    struct bfd* m_bfd;
    bfd_symbol** m_bfdSyms;
    bfd_symbol** m_dynamicBfdSyms;
    bfd_symbol** m_syntheticBfdSyms;
    bfd_symbol* m_rawSyntheticBfdSyms;


    BfdSectionContents_t m_sectionContents;
    BfdSectionByAddress_t m_sectionByAddress;
};

} // namespace emilpro
