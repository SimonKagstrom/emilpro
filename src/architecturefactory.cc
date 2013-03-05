#include <stdlib.h>
#include <architecturefactory.hh>

using namespace emilpro;

ArchitectureFactory::ArchitectureFactory() :
		m_architecture(bfd_arch_unknown)
{
	m_architectureNameMap[(unsigned)bfd_arch_m68k] = "m68k";
	m_architectureNameMap[(unsigned)bfd_arch_vax] = "vax";
	m_architectureNameMap[(unsigned)bfd_arch_i960] = "i960";
	m_architectureNameMap[(unsigned)bfd_arch_or32] = "or32";
	m_architectureNameMap[(unsigned)bfd_arch_sparc] = "sparc";
	m_architectureNameMap[(unsigned)bfd_arch_mips] = "mips";
	m_architectureNameMap[(unsigned)bfd_arch_i386] = "i386";
	m_architectureNameMap[(unsigned)bfd_arch_l1om] = "l1om";
	m_architectureNameMap[(unsigned)bfd_arch_k1om] = "k1om";
	m_architectureNameMap[(unsigned)bfd_arch_we32k] = "we32k";
	m_architectureNameMap[(unsigned)bfd_arch_tahoe] = "tahoe";
	m_architectureNameMap[(unsigned)bfd_arch_i860] = "i860";
	m_architectureNameMap[(unsigned)bfd_arch_i370] = "i370";
	m_architectureNameMap[(unsigned)bfd_arch_romp] = "romp";
	m_architectureNameMap[(unsigned)bfd_arch_convex] = "convex";
	m_architectureNameMap[(unsigned)bfd_arch_m88k] = "m88k";
	m_architectureNameMap[(unsigned)bfd_arch_m98k] = "m98k";
	m_architectureNameMap[(unsigned)bfd_arch_pyramid] = "pyramid";
	m_architectureNameMap[(unsigned)bfd_arch_h8300] = "h8300";
	m_architectureNameMap[(unsigned)bfd_arch_pdp11] = "pdp11";
	m_architectureNameMap[(unsigned)bfd_arch_powerpc] = "powerpc";
	m_architectureNameMap[(unsigned)bfd_arch_rs6000] = "rs6000";
	m_architectureNameMap[(unsigned)bfd_arch_hppa] = "hppa";
	m_architectureNameMap[(unsigned)bfd_arch_d10v] = "d10v";
	m_architectureNameMap[(unsigned)bfd_arch_d30v] = "d30v";
	m_architectureNameMap[(unsigned)bfd_arch_dlx] = "dlx";
	m_architectureNameMap[(unsigned)bfd_arch_m68hc11] = "m68hc11";
	m_architectureNameMap[(unsigned)bfd_arch_m68hc12] = "m68hc12";
	m_architectureNameMap[(unsigned)bfd_arch_m9s12x] = "m9s12x";
	m_architectureNameMap[(unsigned)bfd_arch_m9s12xg] = "m9s12xg";
	m_architectureNameMap[(unsigned)bfd_arch_z8k] = "z8k";
	m_architectureNameMap[(unsigned)bfd_arch_h8500] = "h8500";
	m_architectureNameMap[(unsigned)bfd_arch_sh] = "sh";
	m_architectureNameMap[(unsigned)bfd_arch_alpha] = "alpha";
	m_architectureNameMap[(unsigned)bfd_arch_arm] = "arm";
	m_architectureNameMap[(unsigned)bfd_arch_ns32k] = "ns32k";
	m_architectureNameMap[(unsigned)bfd_arch_w65] = "w65";
	m_architectureNameMap[(unsigned)bfd_arch_tic30] = "tic30";
	m_architectureNameMap[(unsigned)bfd_arch_tic4x] = "tic4x";
	m_architectureNameMap[(unsigned)bfd_arch_tic54x] = "tic54x";
	m_architectureNameMap[(unsigned)bfd_arch_tic6x] = "tic6x";
	m_architectureNameMap[(unsigned)bfd_arch_tic80] = "tic80";
	m_architectureNameMap[(unsigned)bfd_arch_v850] = "v850";
	m_architectureNameMap[(unsigned)bfd_arch_arc] = "arc";
	m_architectureNameMap[(unsigned)bfd_arch_m32c] = "m32c";
	m_architectureNameMap[(unsigned)bfd_arch_m32r] = "m32r";
	m_architectureNameMap[(unsigned)bfd_arch_mn10200] = "mn10200";
	m_architectureNameMap[(unsigned)bfd_arch_mn10300] = "mn10300";
	m_architectureNameMap[(unsigned)bfd_arch_fr30] =  "fr30";
	m_architectureNameMap[(unsigned)bfd_arch_moxie] = "moxie";
	m_architectureNameMap[(unsigned)bfd_arch_mcore] = "mcore";
	m_architectureNameMap[(unsigned)bfd_arch_ia64] = "ia64";
	m_architectureNameMap[(unsigned)bfd_arch_ip2k] = "ip2k";
	m_architectureNameMap[(unsigned)bfd_arch_iq2000] = "iq2000";
	m_architectureNameMap[(unsigned)bfd_arch_epiphany] = "epiphany";
	m_architectureNameMap[(unsigned)bfd_arch_mt] =   "mt";
	m_architectureNameMap[(unsigned)bfd_arch_avr] = "avr";
	m_architectureNameMap[(unsigned)bfd_arch_bfin] = "bfin";
	m_architectureNameMap[(unsigned)bfd_arch_cr16] = "cr16";
	m_architectureNameMap[(unsigned)bfd_arch_cr16c] = "cr16c";
	m_architectureNameMap[(unsigned)bfd_arch_crx] = "crx";
	m_architectureNameMap[(unsigned)bfd_arch_cris] = "cris";
	m_architectureNameMap[(unsigned)bfd_arch_rl78] =  "rl78";
	m_architectureNameMap[(unsigned)bfd_arch_s390] = "s390";
	m_architectureNameMap[(unsigned)bfd_arch_score] = "score";
	m_architectureNameMap[(unsigned)bfd_arch_openrisc] = "openrisc";
	m_architectureNameMap[(unsigned)bfd_arch_mmix] = "mmix";
	m_architectureNameMap[(unsigned)bfd_arch_xstormy16] =  "xstormy16";
	m_architectureNameMap[(unsigned)bfd_arch_xc16x] = "xc16x";
	m_architectureNameMap[(unsigned)bfd_arch_xgate] = "xgate";
	m_architectureNameMap[(unsigned)bfd_arch_xtensa] = "xtensa";
	m_architectureNameMap[(unsigned)bfd_arch_z80] = "z80";
	m_architectureNameMap[(unsigned)bfd_arch_microblaze] = "microblaze";
	m_architectureNameMap[(unsigned)bfd_arch_tilepro] = "tilepro";
	m_architectureNameMap[(unsigned)bfd_arch_tilegx] = "tilegx";
	m_architectureNameMap[(unsigned)bfd_arch_aarch64] = "aarch64";

	m_nameArchitectureMap["m68k"] = (unsigned)bfd_arch_m68k;
	m_nameArchitectureMap["vax"] = (unsigned)bfd_arch_vax;
	m_nameArchitectureMap["i960"] = (unsigned)bfd_arch_i960;
	m_nameArchitectureMap["or32"] = (unsigned)bfd_arch_or32;
	m_nameArchitectureMap["sparc"] = (unsigned)bfd_arch_sparc;
	m_nameArchitectureMap["mips"] = (unsigned)bfd_arch_mips;
	m_nameArchitectureMap["i386"] = (unsigned)bfd_arch_i386;
	m_nameArchitectureMap["l1om"] = (unsigned)bfd_arch_l1om;
	m_nameArchitectureMap["k1om"] = (unsigned)bfd_arch_k1om;
	m_nameArchitectureMap["we32k"] = (unsigned)bfd_arch_we32k;
	m_nameArchitectureMap["tahoe"] = (unsigned)bfd_arch_tahoe;
	m_nameArchitectureMap["i860"] = (unsigned)bfd_arch_i860;
	m_nameArchitectureMap["i370"] = (unsigned)bfd_arch_i370;
	m_nameArchitectureMap["romp"] = (unsigned)bfd_arch_romp;
	m_nameArchitectureMap["convex"] = (unsigned)bfd_arch_convex;
	m_nameArchitectureMap["m88k"] = (unsigned)bfd_arch_m88k;
	m_nameArchitectureMap["m98k"] = (unsigned)bfd_arch_m98k;
	m_nameArchitectureMap["pyramid"] = (unsigned)bfd_arch_pyramid;
	m_nameArchitectureMap["h8300"] = (unsigned)bfd_arch_h8300;
	m_nameArchitectureMap["pdp11"] = (unsigned)bfd_arch_pdp11;
	m_nameArchitectureMap["powerpc"] = (unsigned)bfd_arch_powerpc;
	m_nameArchitectureMap["rs6000"] = (unsigned)bfd_arch_rs6000;
	m_nameArchitectureMap["hppa"] = (unsigned)bfd_arch_hppa;
	m_nameArchitectureMap["d10v"] = (unsigned)bfd_arch_d10v;
	m_nameArchitectureMap["d30v"] = (unsigned)bfd_arch_d30v;
	m_nameArchitectureMap["dlx"] = (unsigned)bfd_arch_dlx;
	m_nameArchitectureMap["m68hc11"] = (unsigned)bfd_arch_m68hc11;
	m_nameArchitectureMap["m68hc12"] = (unsigned)bfd_arch_m68hc12;
	m_nameArchitectureMap["m9s12x"] = (unsigned)bfd_arch_m9s12x;
	m_nameArchitectureMap["m9s12xg"] = (unsigned)bfd_arch_m9s12xg;
	m_nameArchitectureMap["z8k"] = (unsigned)bfd_arch_z8k;
	m_nameArchitectureMap["h8500"] = (unsigned)bfd_arch_h8500;
	m_nameArchitectureMap["sh"] = (unsigned)bfd_arch_sh;
	m_nameArchitectureMap["alpha"] = (unsigned)bfd_arch_alpha;
	m_nameArchitectureMap["arm"] = (unsigned)bfd_arch_arm;
	m_nameArchitectureMap["ns32k"] = (unsigned)bfd_arch_ns32k;
	m_nameArchitectureMap["w65"] = (unsigned)bfd_arch_w65;
	m_nameArchitectureMap["tic30"] = (unsigned)bfd_arch_tic30;
	m_nameArchitectureMap["tic4x"] = (unsigned)bfd_arch_tic4x;
	m_nameArchitectureMap["tic54x"] = (unsigned)bfd_arch_tic54x;
	m_nameArchitectureMap["tic6x"] = (unsigned)bfd_arch_tic6x;
	m_nameArchitectureMap["tic80"] = (unsigned)bfd_arch_tic80;
	m_nameArchitectureMap["v850"] = (unsigned)bfd_arch_v850;
	m_nameArchitectureMap["arc"] = (unsigned)bfd_arch_arc;
	m_nameArchitectureMap["m32c"] = (unsigned)bfd_arch_m32c;
	m_nameArchitectureMap["m32r"] = (unsigned)bfd_arch_m32r;
	m_nameArchitectureMap["mn10200"] = (unsigned)bfd_arch_mn10200;
	m_nameArchitectureMap["mn10300"] = (unsigned)bfd_arch_mn10300;
	m_nameArchitectureMap["fr30"] =  (unsigned)bfd_arch_fr30;
	m_nameArchitectureMap["moxie"] = (unsigned)bfd_arch_moxie;
	m_nameArchitectureMap["mcore"] = (unsigned)bfd_arch_mcore;
	m_nameArchitectureMap["ia64"] = (unsigned)bfd_arch_ia64;
	m_nameArchitectureMap["ip2k"] = (unsigned)bfd_arch_ip2k;
	m_nameArchitectureMap["iq2000"] = (unsigned)bfd_arch_iq2000;
	m_nameArchitectureMap["epiphany"] = (unsigned)bfd_arch_epiphany;
	m_nameArchitectureMap["mt"] =   (unsigned)bfd_arch_mt;
	m_nameArchitectureMap["avr"] = (unsigned)bfd_arch_avr;
	m_nameArchitectureMap["bfin"] = (unsigned)bfd_arch_bfin;
	m_nameArchitectureMap["cr16"] = (unsigned)bfd_arch_cr16;
	m_nameArchitectureMap["cr16c"] = (unsigned)bfd_arch_cr16c;
	m_nameArchitectureMap["crx"] = (unsigned)bfd_arch_crx;
	m_nameArchitectureMap["cris"] = (unsigned)bfd_arch_cris;
	m_nameArchitectureMap["rl78"] =  (unsigned)bfd_arch_rl78;
	m_nameArchitectureMap["s390"] = (unsigned)bfd_arch_s390;
	m_nameArchitectureMap["score"] = (unsigned)bfd_arch_score;
	m_nameArchitectureMap["openrisc"] = (unsigned)bfd_arch_openrisc;
	m_nameArchitectureMap["mmix"] = (unsigned)bfd_arch_mmix;
	m_nameArchitectureMap["xstormy16"] =  (unsigned)bfd_arch_xstormy16;
	m_nameArchitectureMap["xc16x"] = (unsigned)bfd_arch_xc16x;
	m_nameArchitectureMap["xgate"] = (unsigned)bfd_arch_xgate;
	m_nameArchitectureMap["xtensa"] = (unsigned)bfd_arch_xtensa;
	m_nameArchitectureMap["z80"] = (unsigned)bfd_arch_z80;
	m_nameArchitectureMap["microblaze"] = (unsigned)bfd_arch_microblaze;
	m_nameArchitectureMap["tilepro"] = (unsigned)bfd_arch_tilepro;
	m_nameArchitectureMap["tilegx"] = (unsigned)bfd_arch_tilegx;
	m_nameArchitectureMap[ "aarch64"] = (unsigned)bfd_arch_aarch64;
}

std::string& ArchitectureFactory::getNameFromArchitecture(ArchitectureFactory::Architecture_t arch)
{
	ArchitectureFactory::ArchitectureNameMap_t::iterator it = m_architectureNameMap.find((unsigned)arch);

	if (it == m_architectureNameMap.end())
		return m_unknownArchitecture;

	return it->second;
}

ArchitectureFactory::Architecture_t ArchitectureFactory::getArchitectureFromName(std::string name)
{
	ArchitectureFactory::NameArchitectureMap_t::iterator it = m_nameArchitectureMap.find(name);

	if (it == m_nameArchitectureMap.end())
		return bfd_arch_unknown;

	return (Architecture_t)it->second;
}

ArchitectureFactory::~ArchitectureFactory()
{
}


void ArchitectureFactory::registerListener(IArchitectureListener *listener)
{
	listener->onArchitectureDetected(m_architecture);

	m_listeners.push_back(listener);
}

void ArchitectureFactory::provideArchitecture(Architecture_t arch)
{
	if (arch == m_architecture)
		return;

	m_architecture = arch;

	for (ArchitectureListeners_t::iterator it = m_listeners.begin();
			it != m_listeners.end();
			++it) {
		IArchitectureListener *cur = *it;

		cur->onArchitectureDetected(m_architecture);
	}
}



static ArchitectureFactory *g_instance;
void ArchitectureFactory::destroy()
{
	g_instance = NULL;
	delete this;
}

ArchitectureFactory & ArchitectureFactory::instance()
{

	if (!g_instance)
		g_instance = new ArchitectureFactory();

	return *g_instance;
}
