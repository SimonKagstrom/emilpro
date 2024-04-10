#include "elf_binary_parser.hh"

#include <array>
#include <bfd.h>
#include <cassert>
#include <fcntl.h>
#include <fmt/format.h>
#include <list>
#include <map>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_map>

using namespace emilpro;

// ELF machine to the Machine enum mapping
constexpr auto kMachineMap = std::array {
    std::pair {bfd_arch_i386, Machine::kX86},
    std::pair {bfd_arch_mips, Machine::kMips},
    std::pair {bfd_arch_powerpc, Machine::kPpc},
    std::pair {bfd_arch_arm, Machine::kArm},
    std::pair {bfd_arch_aarch64, Machine::kAmd64},
};


struct target_buffer
{
    uint8_t* base;
    size_t size;
};

// Helpers for libbfd
/* Opening the file is a no-op.  */
static void*
mem_bfd_iovec_open(struct bfd* abfd, void* open_closure)
{
    return open_closure;
}

/* Closing the file is just freeing the base/size pair on our side.  */

static int
mem_bfd_iovec_close(struct bfd* abfd, void* stream)
{
    free(stream);
    return 1;
}

/* For reading the file, we just need to pass through to target_read_memory and
   fix up the arguments and return values.  */

static file_ptr
mem_bfd_iovec_pread(struct bfd* abfd, void* stream, void* buf, file_ptr nbytes, file_ptr offset)
{
    struct target_buffer* buffer = (struct target_buffer*)stream;

    /* If this read will read all of the file, limit it to just the rest.  */
    if (offset + nbytes > (ssize_t)buffer->size)
        nbytes = buffer->size - offset;

    /* If there are no more bytes left, we've reached EOF.  */
    if (nbytes == 0)
        return 0;

    memcpy(buf, buffer->base + offset, nbytes);

    return nbytes;
}

/* For statting the file, we only support the st_size attribute.  */
static int
mem_bfd_iovec_stat(struct bfd* abfd, void* stream, struct stat* sb)
{
    struct target_buffer* buffer = (struct target_buffer*)stream;

    sb->st_size = buffer->size;
    return 0;
}


ElfBinaryParser::ElfBinaryParser(std::string_view path)
    : m_path(path)
    , m_rawData(NULL)
    , m_rawDataSize(0)
    , m_bfd(NULL)
    , m_bfdSyms(NULL)
    , m_dynamicBfdSyms(NULL)
    , m_syntheticBfdSyms(NULL)
    , m_rawSyntheticBfdSyms(NULL)
{
}

ElfBinaryParser::~ElfBinaryParser()
{
    for (BfdSectionContents_t::iterator it = m_sectionContents.begin();
         it != m_sectionContents.end();
         ++it)
    {
        void* p = it->second;

        free(p);
    }

    if (m_bfd)
    {
        free(m_bfdSyms);
        free(m_dynamicBfdSyms);
        free(m_syntheticBfdSyms);
        free(m_rawSyntheticBfdSyms);
        bfd_close(m_bfd);
        m_bfd = nullptr;
    }
}

Machine
ElfBinaryParser::GetMachine() const
{
    return Machine::kUnknown;
}

void
ElfBinaryParser::ForAllSections(std::function<void(std::unique_ptr<ISection>)> on_section)
{
}


bool
ElfBinaryParser::lookupLine(bfd_section* section, bfd_symbol** symTbl, uint64_t addr)
{
    const char* fileName;
    const char* function;
    unsigned int lineNr;

    if (bfd_find_nearest_line(
            m_bfd, section, symTbl, addr - section->vma, &fileName, &function, &lineNr))
    {
        if (!fileName)
            return false;

        //printf("Mopping: %s, %s: %d\n", fileName, function, lineNr);
    }

    return false; // lp->m_isValid;
}

// From ILineProvider
bool
ElfBinaryParser::getLineByAddress(uint64_t addr)
{
    //ILineProvider::FileLine out;
    bool out = false;

    BfdSectionByAddress_t::iterator it = m_sectionByAddress.lower_bound(addr);
    if (it == m_sectionByAddress.end())
    {
        return out;
    }

    bfd_section* section = it->second;

    if (!section)
        return out;

    //        if (lookupLine(&out, section, m_bfdSyms, addr))
    //            return out;
    //
    //        if (lookupLine(&out, section, m_dynamicBfdSyms, addr))
    //            return out;

    return out;
}

bool
ElfBinaryParser::Parse()
{
    char** matching;
    unsigned int sz;
    struct target_buffer* buffer = (struct target_buffer*)malloc(sizeof(struct target_buffer));
    bool isElf;

    // Mmap file
    struct stat filestat;

    auto fd = open(m_path.data(), O_RDONLY);
    assert(fd != -1);
    if (fstat(fd, &filestat) != 0)
    {
        perror("stat failed");
        exit(1);
    }
    auto data = mmap(NULL, filestat.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (data == MAP_FAILED)
    {
        perror("mmap failed");
        exit(2);
    }

    buffer->base = (uint8_t*)data;
    buffer->size = filestat.st_size;
    m_rawData = (uint8_t*)data;
    m_rawDataSize = filestat.st_size;
    m_bfd = bfd_openr_iovec("",
                            NULL,
                            mem_bfd_iovec_open,
                            buffer,
                            mem_bfd_iovec_pread,
                            mem_bfd_iovec_close,
                            mem_bfd_iovec_stat);

    if (!m_bfd)
    {
        //            error("bfd_openr failed");
        return false;
    }
    if (!bfd_check_format_matches(m_bfd, bfd_object, &matching))
    {
        printf("not matching %s\n", bfd_errmsg(bfd_get_error()));
        bfd_close(m_bfd);
        m_bfd = NULL;
        return false;
    }

    auto arch = bfd_get_arch(m_bfd);

    //        isElf = memcmp(m_rawData, ELFMAG, SELFMAG) == 0;
    //
    //        if (bfd_get_arch(m_bfd) == bfd_arch_unknown)
    //            guessArchitecture(data, dataSize);
    //        ArchitectureFactory::instance().provideArchitecture(
    //            (ArchitectureFactory::Architecture_t)bfd_get_arch(m_bfd), bfd_get_mach(m_bfd));
    //
    //
    long symcount, dynsymcount, syntsymcount;

    symcount = bfd_read_minisymbols(m_bfd, FALSE, (void**)&m_bfdSyms, &sz);

    handleSymbols(symcount, m_bfdSyms, false);

    dynsymcount = bfd_read_minisymbols(m_bfd, TRUE /* dynamic */, (void**)&m_dynamicBfdSyms, &sz);
    handleSymbols(dynsymcount, m_dynamicBfdSyms, true);

    bfd_symbol* syntheticSyms;
    syntsymcount = bfd_get_synthetic_symtab(
        m_bfd, symcount, m_bfdSyms, dynsymcount, m_dynamicBfdSyms, &syntheticSyms);

    if (syntheticSyms)
    {
        m_rawSyntheticBfdSyms = syntheticSyms;
        m_syntheticBfdSyms = (bfd_symbol**)malloc(syntsymcount * sizeof(bfd_symbol*));
        for (long i = 0; i < syntsymcount; i++)
            m_syntheticBfdSyms[i] = &syntheticSyms[i];
        handleSymbols(syntsymcount, m_syntheticBfdSyms, false);
    }

    //    deriveSymbolSizes();

    // Provide section symbols
    bfd_section* section;
    for (section = m_bfd->sections; section != NULL; section = section->next)
    {
        //            m_sectionByAddress[(uint64_t)bfd_section_vma(m_bfd, section)] = section;

        // Skip non-allocated sections
        if ((section->flags & SEC_ALLOC) == 0)
            continue;

        BfdSectionContents_t::iterator it = m_sectionContents.find(section);
        if (it == m_sectionContents.end())
        {
            bfd_size_type size;
            bfd_byte* p;

            size = bfd_section_size(section);
            p = (bfd_byte*)malloc(size);

            if (!bfd_get_section_contents(m_bfd, section, p, 0, size))
            {
                free((void*)p);
                continue;
            }

            m_sectionContents[section] = p;
            it = m_sectionContents.find(section);
        }
    }

    // The first pass has created symbols, now look for relocations
    for (section = m_bfd->sections; section != NULL; section = section->next)
    {
        uint64_t addr = bfd_section_vma(section);
        //            m_sectionByAddress[(uint64_t)bfd_section_vma(m_bfd, section)] = section;

        if (section->reloc_count > 0)
        {
            for (auto i = 0; i < section->reloc_count; i++)
            {
                if (section->relocation)
                {
                    auto& reloc = section->relocation[i];
                    printf("Reloc for %20s: addend: 0x%08x, address 0x%08x. sz: %d\n",
                           (*reloc.sym_ptr_ptr)->name,
                           reloc.addend,
                           reloc.address,
                           bfd_get_reloc_size(reloc.howto));
                }
            }
            //handleRelocations(section);
        }
    }

    // Add the file symbol
    //        ISymbol& sym = SymbolFactory::instance().createSymbol(ISymbol::LINK_NORMAL,
    //                                                              ISymbol::SYM_FILE,
    //                                                              "file",
    //                                                              data,
    //                                                              0,
    //                                                              dataSize,
    //                                                              0,
    //                                                              false,
    //                                                              false,
    //                                                              false,
    //                                                              0);
    //
    //        m_listener->onSymbol(sym);

    return true;
}

void
ElfBinaryParser::handleSymbols(long symcount, bfd_symbol** syms, bool dynamic)
{
    for (long i = 0; i < symcount; i++)
    {
        auto cur = syms[i];

        if (!cur)
            continue;

        auto symName = bfd_asymbol_name(cur);
        auto symAddr = bfd_asymbol_value(cur);
        auto section = bfd_asymbol_section(cur);
        printf("%s Symbol: %s @ 0x%08x in section %s\n",
               dynamic ? "DYNAMIC" : "",
               symName,
               (int)symAddr,
               section->name);

        lookupLine(section, m_bfdSyms, symAddr);
    }
}
