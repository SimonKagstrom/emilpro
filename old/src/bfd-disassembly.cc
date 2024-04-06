#include <stdio.h>
#include <stdint.h>

#include <map>
#include <vector>
#include <functional>

#include <string.h> // binutils 2.29 wants strchr

#include <bfd.h>
#include <dis-asm.h>

#include <architecturefactory.hh>
#include <instructionfactory.hh>
#include <idisassemblyprovider.hh>
#include <iinstruction.hh>
#include <preferences.hh>
#include <utils.hh>

using namespace emilpro;

class Disassembly : public
	ArchitectureFactory::IArchitectureListener,
	Preferences::IListener
{
public:
	Disassembly()
	{
		memset(&m_info, 0, sizeof(m_info));
	    m_list = NULL;
	    m_startAddress = 0;
	    m_disassembler = NULL;
	    m_encoding = NULL;
	    m_useIntelSyntax = false;

	    m_arch[bfd_arch_i386] = BfdArch(bfd_arch_i386, bfd_mach_i386_i386, print_insn_i386);
	    m_arch[bfd_arch_powerpc] = BfdArch(bfd_arch_powerpc, bfd_mach_ppc_e500mc64, print_insn_big_powerpc);
	    m_arch[bfd_arch_arm] = BfdArch(bfd_arch_arm, bfd_mach_arm_unknown, print_insn_little_arm);
	    m_arch[bfd_arch_mips] = BfdArch(bfd_arch_mips, bfd_mach_mips10000, print_insn_big_mips);

	    m_arch[bfd_arch_m68k] = BfdArch(bfd_arch_m68k, bfd_mach_m68040, print_insn_m68k);      /* Motorola 68xxx */
	    m_arch[bfd_arch_vax] = BfdArch(bfd_arch_vax, 0, print_insn_vax);       /* DEC Vax */
	    m_arch[bfd_arch_i960] = BfdArch(bfd_arch_i960, 0, print_insn_i960);      /* Intel 960 */
	    m_arch[bfd_arch_or1k] = BfdArch(bfd_arch_or1k, 0, print_insn_or1k);      /* OpenRISC 32 */
	    m_arch[bfd_arch_sparc] = BfdArch(bfd_arch_sparc, 0, print_insn_sparc);     /* SPARC */
	    m_arch[bfd_arch_spu] = BfdArch(bfd_arch_spu, 0, print_insn_spu);       /* PowerPC SPU */
	    m_arch[bfd_arch_i860] = BfdArch(bfd_arch_i860, 0, print_insn_i860);      /* Intel 860 */
	    m_arch[bfd_arch_i370] = BfdArch(bfd_arch_i370, 0, print_insn_i370);      /* IBM 360/370 Mainframes */
	    m_arch[bfd_arch_m88k] = BfdArch(bfd_arch_m88k, 0, print_insn_m88k);      /* Motorola 88xxx */
	    m_arch[bfd_arch_h8300] = BfdArch(bfd_arch_h8300, 0, print_insn_h8300);     /* Renesas H8/300 (formerly Hitachi H8/300) */
	    m_arch[bfd_arch_pdp11] = BfdArch(bfd_arch_pdp11, 0, print_insn_pdp11);     /* DEC PDP-11 */
	    m_arch[bfd_arch_rs6000] = BfdArch(bfd_arch_rs6000, bfd_mach_rs6k_rs2, print_insn_rs6000);    /* IBM RS/6000 */
	    m_arch[bfd_arch_hppa] = BfdArch(bfd_arch_hppa, 0, print_insn_hppa);      /* HP PA RISC */
	    m_arch[bfd_arch_d10v] = BfdArch(bfd_arch_d10v, 0, print_insn_d10v);      /* Mitsubishi D10V */
	    m_arch[bfd_arch_d30v] = BfdArch(bfd_arch_d30v, 0, print_insn_d30v);      /* Mitsubishi D30V */
	    m_arch[bfd_arch_dlx] = BfdArch(bfd_arch_dlx, 0, print_insn_dlx);       /* DLX */
	    m_arch[bfd_arch_m68hc11] = BfdArch(bfd_arch_m68hc11, 0, print_insn_m68hc11);   /* Motorola 68HC11 */
	    m_arch[bfd_arch_m68hc12] = BfdArch(bfd_arch_m68hc12, 0, print_insn_m68hc12);   /* Motorola 68HC12 */
	    m_arch[bfd_arch_m9s12x] = BfdArch(bfd_arch_m9s12x, 0, print_insn_m9s12x);   /* Freescale S12X */
	    m_arch[bfd_arch_m9s12xg] = BfdArch(bfd_arch_m9s12xg, 0, print_insn_m9s12xg);  /* Freescale XGATE */
	    m_arch[bfd_arch_h8500] = BfdArch(bfd_arch_h8500, 0, print_insn_h8500);     /* Renesas H8/500 (formerly Hitachi H8/500) */
	    m_arch[bfd_arch_sh] = BfdArch(bfd_arch_sh, 0, print_insn_sh);        /* Renesas / SuperH SH (formerly Hitachi SH) */
	    m_arch[bfd_arch_alpha] = BfdArch(bfd_arch_alpha, 0, print_insn_alpha);     /* Dec Alpha */
	    m_arch[bfd_arch_ns32k] = BfdArch(bfd_arch_ns32k, 0, print_insn_ns32k);     /* National Semiconductors ns32000 */
	    m_arch[bfd_arch_w65] = BfdArch(bfd_arch_w65, 0, print_insn_w65);       /* WDC 65816 */
	    m_arch[bfd_arch_tic30] = BfdArch(bfd_arch_tic30, 0, print_insn_tic30);     /* Texas Instruments TMS320C30 */
	    m_arch[bfd_arch_tic4x] = BfdArch(bfd_arch_tic4x, 0, print_insn_tic4x);     /* Texas Instruments TMS320C3X/4X */
	    m_arch[bfd_arch_tic54x] = BfdArch(bfd_arch_tic54x, 0, print_insn_tic54x);    /* Texas Instruments TMS320C54X */
	    m_arch[bfd_arch_tic6x] = BfdArch(bfd_arch_tic6x, 0, print_insn_tic6x);     /* Texas Instruments TMS320C6X */
	    m_arch[bfd_arch_tic80] = BfdArch(bfd_arch_tic80, 0, print_insn_tic80);     /* TI TMS320c80 (MVP) */
	    m_arch[bfd_arch_v850] = BfdArch(bfd_arch_v850, 0, print_insn_v850);      /* NEC V850 */
	    m_arch[bfd_arch_m32c] = BfdArch(bfd_arch_m32c, 0, print_insn_m32c);     /* Renesas M16C/M32C.  */
	    m_arch[bfd_arch_m32r] = BfdArch(bfd_arch_m32r, 0, print_insn_m32r);      /* Renesas M32R (formerly Mitsubishi M32R/D) */
	    m_arch[bfd_arch_mn10200] = BfdArch(bfd_arch_mn10200, 0, print_insn_mn10200);   /* Matsushita MN10200 */
	    m_arch[bfd_arch_mn10300] = BfdArch(bfd_arch_mn10300, 0, print_insn_mn10300);   /* Matsushita MN10300 */
	    m_arch[bfd_arch_fr30] = BfdArch(bfd_arch_fr30, 0, print_insn_fr30);
	    m_arch[bfd_arch_frv] = BfdArch(bfd_arch_frv, 0, print_insn_frv);
	    m_arch[bfd_arch_moxie] = BfdArch(bfd_arch_moxie, 0, print_insn_moxie);       /* The moxie processor */
	    m_arch[bfd_arch_mep] = BfdArch(bfd_arch_mep, 0, print_insn_mep);
	    m_arch[bfd_arch_mcore] = BfdArch(bfd_arch_mcore, 0, print_insn_mcore);
	    m_arch[bfd_arch_ia64] = BfdArch(bfd_arch_ia64, bfd_mach_ia64_elf64, print_insn_ia64);      /* HP/Intel ia64 */
	    m_arch[bfd_arch_ip2k] = BfdArch(bfd_arch_ip2k, 0, print_insn_ip2k);      /* Ubicom IP2K microcontrollers. */
	    m_arch[bfd_arch_iq2000] = BfdArch(bfd_arch_iq2000, 0, print_insn_iq2000);     /* Vitesse IQ2000.  */
	    m_arch[bfd_arch_epiphany] = BfdArch(bfd_arch_epiphany, 0, print_insn_epiphany);   /* Adapteva EPIPHANY */
	    m_arch[bfd_arch_mt] = BfdArch(bfd_arch_mt, 0, print_insn_mt);
	    m_arch[bfd_arch_pj] = BfdArch(bfd_arch_pj, 0, print_insn_pj);
	    m_arch[bfd_arch_avr] = BfdArch(bfd_arch_avr, bfd_mach_avr6, print_insn_avr);       /* Atmel AVR microcontrollers.  */
	    m_arch[bfd_arch_bfin] = BfdArch(bfd_arch_bfin, 0, print_insn_bfin);        /* ADI Blackfin */
	    m_arch[bfd_arch_cr16] = BfdArch(bfd_arch_cr16, 0, print_insn_cr16);       /* National Semiconductor CompactRISC (ie CR16). */
	    m_arch[bfd_arch_crx] = BfdArch(bfd_arch_crx, 0, print_insn_crx);       /*  National Semiconductor CRX.  */
	    m_arch[bfd_arch_cris] = BfdArch(bfd_arch_cris, 0, cris_get_disassembler(NULL));      /* Axis CRIS */
	    m_arch[bfd_arch_rl78] = BfdArch(bfd_arch_rl78, 0, print_insn_rl78);
	    m_arch[bfd_arch_rx] = BfdArch(bfd_arch_rx, 0, print_insn_rx);        /* Renesas RX.  */
	    m_arch[bfd_arch_s390] = BfdArch(bfd_arch_s390, bfd_mach_s390_64, print_insn_s390);      /* IBM s390 */
	    m_arch[bfd_arch_mmix] = BfdArch(bfd_arch_mmix, 0, print_insn_mmix);      /* Donald Knuth's educational processor.  */
	    m_arch[bfd_arch_xstormy16] = BfdArch(bfd_arch_xstormy16, 0, print_insn_xstormy16);
	    m_arch[bfd_arch_msp430] = BfdArch(bfd_arch_msp430, 0, print_insn_msp430);    /* Texas Instruments MSP430 architecture.  */
	    m_arch[bfd_arch_xc16x] = BfdArch(bfd_arch_xc16x, 0, print_insn_xc16x);     /* Infineon's XC16X Series.               */
	    m_arch[bfd_arch_xgate] = BfdArch(bfd_arch_xgate, 0, print_insn_xgate);     /* Freescale XGATE */
	    m_arch[bfd_arch_xtensa] = BfdArch(bfd_arch_xtensa, 0, print_insn_xtensa);    /* Tensilica's Xtensa cores.  */
	    m_arch[bfd_arch_z80] = BfdArch(bfd_arch_z80, bfd_mach_z80full, print_insn_z80);
	    m_arch[bfd_arch_lm32] = BfdArch(bfd_arch_lm32, 0, print_insn_lm32);      /* Lattice Mico32 */
	    m_arch[bfd_arch_microblaze] = BfdArch(bfd_arch_microblaze, 0, print_insn_microblaze);/* Xilinx MicroBlaze. */
	    m_arch[bfd_arch_tilepro] = BfdArch(bfd_arch_tilepro, 0, print_insn_tilepro);   /* Tilera TILEPro */
	    m_arch[bfd_arch_tilegx] = BfdArch(bfd_arch_tilegx, 0, print_insn_tilegx);    /* Tilera TILE-Gx */
	    m_arch[bfd_arch_aarch64] = BfdArch(bfd_arch_aarch64, 0, print_insn_aarch64);   /* AArch64  */

	    // Some "sane" default
		m_currentArch = BfdArch(m_arch[bfd_arch_i386]);
		m_mangler = mangleGenericEncodingVector;
	}

	void init()
	{
		setArchitecture(m_currentArch);

	    ArchitectureFactory::instance().registerListener(this);
	    Preferences::instance().registerListener("X86InstructionSyntax", this);
	}

	virtual ~Disassembly()
	{
	    Preferences::instance().unregisterListener(this);
	}

	virtual void onPreferencesChanged(const std::string &key,
			const std::string &oldValue, const std::string &newValue)
	{
		if (key != "X86InstructionSyntax")
			return;

		m_useIntelSyntax = (newValue == "intel");
		setArchitecture(m_currentArch);
	}


	virtual void onArchitectureDetected(ArchitectureFactory::Architecture_t arch,
			ArchitectureFactory::Machine_t machine)
	{
		ArchitectureBfdMap_t::iterator it = m_arch.find(arch);

		if (it != m_arch.end())
		{
			m_currentArch = it->second;
			m_currentArch.bfd_mach = machine;

			setArchitecture(m_currentArch);
		}
	}

	InstructionList_t execute(void *p, size_t size, uint64_t address)
	{
		InstructionList_t out;
		uint8_t *data = (uint8_t *)p;

		if (!data || size == 0)
			return out;

		InstructionFactory &factory = InstructionFactory::instance();

		m_list = &out;
		m_startAddress = address;

		m_info.buffer_vma = 0;
		m_info.buffer_length = size;
		m_info.buffer = (bfd_byte *)p;
		m_info.stream = (void *)this;

		uint64_t pc = 0;
		int count;
		do
		{
			m_instructionStr.clear();
			m_instructionVector.clear();
			count = m_disassembler(pc, &m_info);

			if (count < 0)
				break;

			IInstruction *insn = factory.create(m_startAddress, pc, m_instructionVector,
					m_instructionStr, (uint8_t *)p + pc, count);

			if (insn)
				m_list->push_back(insn);

			pc += count;
		} while (count > 0 && pc < size);

		return out;
	}

	void destroy();

private:
	class BfdArch
	{
	public:
		BfdArch() :
			bfd_arch(bfd_arch_i386),
			bfd_mach(0),
			callback(NULL)
		{
		}

		BfdArch(enum bfd_architecture arch,	unsigned long mach, disassembler_ftype cb) :
			bfd_arch(arch), bfd_mach(mach), callback(cb)
		{
		}

		enum bfd_architecture bfd_arch;
		unsigned long bfd_mach;
		disassembler_ftype callback;
	};

	static const std::vector<std::string> mangleGenericEncodingVector(std::vector<std::string> &encodingVector)
	{
		return encodingVector;
	}

	static const std::vector<std::string> mangleArmEncodingVector(std::vector<std::string> &encodingVector)
	{
		std::vector<std::string> out;

		std::string cur;
		for (std::vector<std::string>::iterator it = encodingVector.begin();
				it != encodingVector.end();
				++it) {
			std::string s = *it;

			if (s[0] == ',' || s[0] == ' ' || s[0] == '\t') {
				out.push_back(cur);
				cur = "";
			}

			cur += s;
		}

		if (cur != "")
			out.push_back(cur);

		return out;
	}

	static const std::vector<std::string> manglePowerPcEncodingVector(std::vector<std::string> &encodingVector)
	{
		std::vector<std::string> out;

		std::string cur;
		size_t sz = encodingVector.size();

		unsigned i = 0;
		for (std::vector<std::string>::iterator it = encodingVector.begin();
				it != encodingVector.end();
				++it) {
			std::string s = *it;

			cur += s;
			if (s == "," || i == 0 || (i == sz - 1)) {
				out.push_back(cur);
				cur = "";
			}
			i++;
		}

		return out;
	}

	typedef std::map<ArchitectureFactory::Architecture_t, BfdArch> ArchitectureBfdMap_t;

	void setArchitecture(const BfdArch &arch)
	{
		init_disassemble_info(&m_info, (void *)this, Disassembly::opcodesFprintFuncStatic);
		unsigned long bfd_mach = arch.bfd_mach;

		m_mangler = mangleGenericEncodingVector;

		if (arch.bfd_arch == bfd_arch_i386) {
			if (m_useIntelSyntax)
				bfd_mach |= bfd_mach_i386_intel_syntax;
			else
				bfd_mach &= ~bfd_mach_i386_intel_syntax;
		} else if (arch.bfd_arch == bfd_arch_arm) {
			m_mangler = mangleArmEncodingVector;
		} else if (arch.bfd_arch == bfd_arch_powerpc) {
			m_mangler = manglePowerPcEncodingVector;
		}

		m_info.arch = arch.bfd_arch;
		m_info.mach = bfd_mach;
		m_disassembler = arch.callback;
		disassemble_init_for_target(&m_info);
		m_info.application_data = (void *)this;
	}

	void opcodesFprintFunc(const char *str)
	{
		std::string stdStr(str);

		m_instructionVector.push_back(trimString(stdStr));
		m_instructionStr += str;
	}

	static int opcodesFprintFuncStatic(void *info, const char *fmt, ...)
	{
	    Disassembly *pThis = (Disassembly *)info;
		char str[64];
	    int out;

	    va_list args;
	    va_start (args, fmt);
	    out = vsnprintf( str, sizeof(str) - 1, fmt, args );
	    va_end (args);

	    pThis->opcodesFprintFunc(str);

	    return out;
	}

	struct disassemble_info m_info;
	disassembler_ftype m_disassembler;
	ArchitectureBfdMap_t m_arch;
	BfdArch m_currentArch;

	InstructionList_t *m_list;
	uint64_t m_startAddress;
	uint8_t *m_encoding;

	std::string m_instructionStr;
	std::vector<std::string> m_instructionVector;
	std::function<const std::vector<std::string>(std::vector<std::string> &encodingVector)> m_mangler;

	bool m_useIntelSyntax;
};


class BfdDisassemblerProvider : public IDisassemblyProvider,
	public std::enable_shared_from_this<IDisassemblyProvider>
{
public:
	BfdDisassemblerProvider()
	{
		InstructionFactory::instance().registerProvider(std::shared_ptr<IDisassemblyProvider>(this));
	}

	virtual ~BfdDisassemblerProvider()
	{
	}

	unsigned match(void *data, size_t dataSize)
	{
		if (!m_instance) {
			m_instance = std::unique_ptr<Disassembly>(new Disassembly());

			m_instance->init();
		}

		// BFD should be the fallback solution - but not a perfect one
		return 100;
	}

	InstructionList_t execute(void *data, size_t size, uint64_t address)
	{
		return m_instance->execute(data, size, address);
	}

	bool relativeAddressOffsets()
	{
		return true;
	}

private:
	std::unique_ptr<Disassembly> m_instance;
};

class DisassemblyCreator
{
public:
	DisassemblyCreator()
	{
		// Deleted by the shared_ptr above
		new BfdDisassemblerProvider();
	}
};

static DisassemblyCreator g_bfdDisassembler;
