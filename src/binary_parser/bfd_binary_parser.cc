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


BfdBinaryParser::BfdBinaryParser(std::string_view path)
    : m_path(path)
    , m_rawData(NULL)
    , m_rawDataSize(0)
    , m_bfd(NULL)
    , m_bfd_syms(NULL)
    , m_dynamicBfdSyms(NULL)
    , m_syntheticBfdSyms(NULL)
    , m_rawSyntheticBfdSyms(NULL)
{
}

BfdBinaryParser::~BfdBinaryParser()
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
        free(m_bfd_syms);
        free(m_dynamicBfdSyms);
        free(m_syntheticBfdSyms);
        free(m_rawSyntheticBfdSyms);
        bfd_close(m_bfd);
        m_bfd = nullptr;
    }
}

Machine
BfdBinaryParser::GetMachine() const
{
    return Machine::kArm;
}

void
BfdBinaryParser::ForAllSections(std::function<void(std::unique_ptr<ISection>)> on_section)
{
    // Provide section symbols
    for (auto section = m_bfd->sections; section != NULL; section = section->next)
    {
        // Skip non-allocated sections
        if ((section->flags & SEC_ALLOC) == 0)
        {
            continue;
        }

        auto size = bfd_section_size(section);
        auto p = new bfd_byte[size];

        if (bfd_get_section_contents(m_bfd, section, p, 0, size))
        {
            auto type = ISection::Type::kData;

            if ((section->flags & SEC_CODE))
            {
                type = ISection::Type::kInstructions;
            }

            auto sec = ISection::Create(std::span<const std::byte>((const std::byte*)p, size),
                                        bfd_section_vma(section),
                                        type);

            on_section(std::move(sec));
        }
        delete[] p;
    }
}


bool
BfdBinaryParser::lookupLine(bfd_section* section, bfd_symbol** symTbl, uint64_t addr)
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
BfdBinaryParser::getLineByAddress(uint64_t addr)
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

static asymbol**
slurp_symtab(bfd* abfd)
{
    asymbol** sy = NULL;
    long storage;

    if (!(bfd_get_file_flags(abfd) & HAS_SYMS))
    {
        return NULL;
    }

    storage = bfd_get_symtab_upper_bound(abfd);
    if (storage < 0)
        exit(1);
    if (storage)
        sy = (asymbol**)malloc(storage);

    auto symcount = bfd_canonicalize_symtab(abfd, sy);
    if (symcount < 0)
        exit(1);
    return sy;
}

static void
dump_relocs_in_section(bfd* abfd, asection* section, auto syms)
{
    arelent** relpp;
    long relcount;
    long relsize;

    if (bfd_is_abs_section(section) || bfd_is_und_section(section) || bfd_is_com_section(section) ||
        ((section->flags & SEC_RELOC) == 0))
        return;
    if ((section->flags & SEC_ALLOC) == 0)
    {
        return;
    }

    relsize = bfd_get_reloc_upper_bound(abfd, section);

    printf("RELOCATION RECORDS FOR [%s]:", section->name);

    if (relsize == 0)
    {
        printf(" (none)\n\n");
        return;
    }

//    auto syms = slurp_symtab(abfd);
    relpp = (arelent**)malloc(relsize);
    relcount = bfd_canonicalize_reloc(abfd, section, relpp, syms);

    if (relcount > 0)
    {
        printf("\n");
        for (auto p = relpp; relcount && *p != NULL; p++, relcount--)
        {
            arelent* q = *p;
            printf("XXX 0x%08x: %s\n", q->address, (*q->sym_ptr_ptr)->name);
        }
    }
    free(relpp);
}

bool
BfdBinaryParser::Parse()
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

    symcount = bfd_read_minisymbols(m_bfd, FALSE, (void**)&m_bfd_syms, &sz);

    handleSymbols(symcount, m_bfd_syms, false);

    dynsymcount = bfd_read_minisymbols(m_bfd, TRUE /* dynamic */, (void**)&m_dynamicBfdSyms, &sz);
    handleSymbols(dynsymcount, m_dynamicBfdSyms, true);

    bfd_symbol* syntheticSyms;
    syntsymcount = bfd_get_synthetic_symtab(
        m_bfd, symcount, m_bfd_syms, dynsymcount, m_dynamicBfdSyms, &syntheticSyms);

    if (syntheticSyms)
    {
        m_rawSyntheticBfdSyms = syntheticSyms;
        m_syntheticBfdSyms = (bfd_symbol**)malloc(syntsymcount * sizeof(bfd_symbol*));
        for (long i = 0; i < syntsymcount; i++)
            m_syntheticBfdSyms[i] = &syntheticSyms[i];
        handleSymbols(syntsymcount, m_syntheticBfdSyms, false);
    }

    //    deriveSymbolSizes();

    // The first pass has created symbols, now look for relocations
    for (auto section = m_bfd->sections; section != NULL; section = section->next)
    {
        dump_relocs_in_section(m_bfd, section, m_bfd_syms);
        continue;

        printf("SECT: %s\n", section->name);
        uint64_t addr = bfd_section_vma(section);
        //            m_sectionByAddress[(uint64_t)bfd_section_vma(m_bfd, section)] = section;

        if (section->reloc_count > 0)
        {
            printf("RELOCS! %d\n", section->reloc_count);
            for (auto i = 0; i < section->reloc_count; i++)
            {
                if (section->relocation)
                {
                    auto& reloc = section->relocation[i];
                    printf("IReloc for 0x%08x in section: %14s: 0x%08x addend: 0x%08x, address "
                           "0x%08x. Type 0x%08x\n",
                           (*reloc.sym_ptr_ptr)->value,
                           (*reloc.sym_ptr_ptr)->section->name,
                           (*reloc.sym_ptr_ptr)->section->filepos,
                           reloc.addend,
                           reloc.address,
                           reloc.howto->type);
                }
                if (section->orelocation)
                {
                    auto reloc = section->orelocation[i];
                    printf("OReloc for %20s: addend: 0x%08x, address 0x%08x.\n",
                           (*reloc->sym_ptr_ptr)->name,
                           reloc->addend,
                           reloc->address);
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
BfdBinaryParser::handleSymbols(long symcount, bfd_symbol** syms, bool dynamic)
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
               bfd_is_und_section(section) ? "(in some other .o file)" : section->name);

        lookupLine(section, m_bfd_syms, symAddr);
    }
}
