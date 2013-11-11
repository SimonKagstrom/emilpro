#include <isymbolprovider.hh>
#include <symbolfactory.hh>

#include <string.h>

using namespace emilpro;

extern "C" char *cplus_demangle (const char *mangled, int options)
{
	return strdup(mangled);
}

class NullProvider : public ISymbolProvider
{
public:
	virtual unsigned match(void *data, size_t dataSize)
	{
		return ISymbolProvider::NO_MATCH;
	}

	virtual bool parse(void *data, size_t dataSize, ISymbolListener *)
	{
		return false;
	}
};

namespace emilpro
{
	ISymbolProvider *createBfdProvider()
	{
		NullProvider *out = new NullProvider();

		SymbolFactory::instance().registerProvider(out);

		return out;
	}
}
