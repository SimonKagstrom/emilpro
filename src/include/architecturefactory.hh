#pragma once

#include <list>

#include <elf.h>

namespace emilpro
{
	class ArchitectureFactory
	{
	public:
		typedef enum
		{
			// From elf.h
			ARCH_UNKNOWN   = EM_NONE,
			ARCH_M32       = EM_M32,           /* AT&T WE 32100 */
			ARCH_SPARC     = EM_SPARC,         /* SUN SPARC */
			ARCH_386       = EM_386,           /* Intel 80386 */
			ARCH_68K       = EM_68K,           /* Motorola m68k family */
			ARCH_88K       = EM_88K,           /* Motorola m88k family */
			ARCH_860       = EM_860,           /* Intel 80860 */
			ARCH_MIPS      = EM_MIPS,          /* MIPS R3000 big-endian */
			ARCH_S370      = EM_S370,          /* IBM System/370 */
			ARCH_MIPS_RS3_LE = EM_MIPS_RS3_LE, /* MIPS R3000 little-endian */

			ARCH_PARISC    = EM_PARISC,        /* HPPA */
			ARCH_VPP500    = EM_VPP500,        /* Fujitsu VPP500 */
			ARCH_SPARC32PLUS = EM_SPARC32PLUS, /* Sun's "v8plus" */
			ARCH_960       = EM_960,           /* Intel 80960 */
			ARCH_PPC       = EM_PPC,           /* PowerPC */
			ARCH_PPC64     = EM_PPC64,         /* PowerPC 64-bit */
			ARCH_S390      = EM_S390,          /* IBM S390 */

			ARCH_V800      = EM_V800,          /* NEC V800 series */
			ARCH_FR20      = EM_FR20,          /* Fujitsu FR20 */
			ARCH_RH32      = EM_RH32,          /* TRW RH-32 */
			ARCH_RCE       = EM_RCE,           /* Motorola RCE */
			ARCH_ARM       = EM_ARM,           /* ARM */
			ARCH_FAKE_ALPHA = EM_FAKE_ALPHA,   /* Digital Alpha */
			ARCH_SH        = EM_SH,            /* Hitachi SH */
			ARCH_SPARCV9   = EM_SPARCV9,       /* SPARC v9 64-bit */
			ARCH_TRICORE   = EM_TRICORE,       /* Siemens Tricore */
			ARCH_ARC       = EM_ARC,           /* Argonaut RISC Core */
			ARCH_H8_300    = EM_H8_300,        /* Hitachi H8/300 */
			ARCH_H8_300H   = EM_H8_300H,       /* Hitachi H8/300H */
			ARCH_H8S       = EM_H8S,           /* Hitachi H8S */
			ARCH_H8_500    = EM_H8_500,        /* Hitachi H8/500 */
			ARCH_IA_64     = EM_IA_64,         /* Intel Merced */
			ARCH_MIPS_X    = EM_MIPS_X,        /* Stanford MIPS-X */
			ARCH_COLDFIRE  = EM_COLDFIRE,      /* Motorola Coldfire */
			ARCH_68HC12    = EM_68HC12,        /* Motorola M68HC12 */
			ARCH_MMA       = EM_MMA,           /* Fujitsu MMA Multimedia Accelerator*/
			ARCH_PCP       = EM_PCP,           /* Siemens PCP */
			ARCH_NCPU      = EM_NCPU,          /* Sony nCPU embeeded RISC */
			ARCH_NDR1      = EM_NDR1,          /* Denso NDR1 microprocessor */
			ARCH_STARCORE  = EM_STARCORE,      /* Motorola Start*Core processor */
			ARCH_ME16      = EM_ME16,          /* Toyota ME16 processor */
			ARCH_ST100     = EM_ST100,         /* STMicroelectronic ST100 processor */
			ARCH_TINYJ     = EM_TINYJ,         /* Advanced Logic Corp. Tinyj emb.fam*/
			ARCH_X86_64    = EM_X86_64,        /* AMD x86-64 architecture */
			ARCH_PDSP      = EM_PDSP,          /* Sony DSP Processor */

			ARCH_FX66      = EM_FX66,          /* Siemens FX66 microcontroller */
			ARCH_ST9PLUS   = EM_ST9PLUS,       /* STMicroelectronics ST9+ 8/16 mc */
			ARCH_ST7       = EM_ST7,           /* STmicroelectronics ST7 8 bit mc */
			ARCH_68HC16    = EM_68HC16,        /* Motorola MC68HC16 microcontroller */
			ARCH_68HC11    = EM_68HC11,        /* Motorola MC68HC11 microcontroller */
			ARCH_68HC08    = EM_68HC08,        /* Motorola MC68HC08 microcontroller */
			ARCH_68HC05    = EM_68HC05,        /* Motorola MC68HC05 microcontroller */
			ARCH_SVX       = EM_SVX,           /* Silicon Graphics SVx */
			ARCH_ST19      = EM_ST19,          /* STMicroelectronics ST19 8 bit mc */
			ARCH_VAX       = EM_VAX,           /* Digital VAX */
			ARCH_CRIS      = EM_CRIS,          /* Axis Communications 32-bit embedded processor */
			ARCH_JAVELIN   = EM_JAVELIN,       /* Infineon Technologies 32-bit embedded processor */
			ARCH_FIREPATH  = EM_FIREPATH,      /* Element 14 64-bit DSP Processor */
			ARCH_ZSP       = EM_ZSP,           /* LSI Logic 16-bit DSP Processor */
			ARCH_MMIX      = EM_MMIX,          /* Donald Knuth's educational 64-bit processor */
			ARCH_HUANY     = EM_HUANY,         /* Harvard University machine-independent object files */
			ARCH_PRISM     = EM_PRISM,         /* SiTera Prism */
			ARCH_AVR       = EM_AVR,           /* Atmel AVR 8-bit microcontroller */
			ARCH_FR30      = EM_FR30,          /* Fujitsu FR30 */
			ARCH_D10V      = EM_D10V,          /* Mitsubishi D10V */
			ARCH_D30V      = EM_D30V,          /* Mitsubishi D30V */
			ARCH_V850      = EM_V850,          /* NEC v850 */
			ARCH_M32R      = EM_M32R,          /* Mitsubishi M32R */
			ARCH_MN10300   = EM_MN10300,       /* Matsushita MN10300 */
			ARCH_MN10200   = EM_MN10200,       /* Matsushita MN10200 */
			ARCH_PJ        = EM_PJ,            /* picoJava */
			ARCH_OPENRISC  = EM_OPENRISC,      /* OpenRISC 32-bit embedded processor */
			ARCH_ARC_A5    = EM_ARC_A5,        /* ARC Cores Tangent-A5 */
			ARCH_XTENSA    = EM_XTENSA,        /* Tensilica Xtensa Architecture */
		} Architecture_t;

		class IArchitectureListener
		{
		public:
			virtual ~IArchitectureListener()
			{
			}

			virtual void onArchitectureDetected(Architecture_t arch) = 0;
		};


		void destroy();

		virtual void registerListener(IArchitectureListener *listener);

		virtual void provideArchitecture(Architecture_t arch);

		static ArchitectureFactory &instance();

	private:
		typedef std::list<IArchitectureListener *> ArchitectureListeners_t;

		ArchitectureFactory();

		virtual ~ArchitectureFactory();

		ArchitectureListeners_t m_listeners;
		Architecture_t m_architecture;
	};
}


