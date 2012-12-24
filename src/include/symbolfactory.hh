#pragma once

#include <list>

#include "symbol.hh"

namespace emilpro
{
	class ISymbolProvider;

	class ISymbolListener
	{
	public:
		virtual ~ISymbolListener()
		{
		}

		virtual void onSymbol(ISymbol &sym) = 0;
	};


	class SymbolFactory
	{
	public:
		void registerListener(ISymbolListener *listener);

		void registerProvider(ISymbolProvider *provider);


		ISymbol &createSymbol(enum ISymbol::LinkageType linkage,
				enum ISymbol::SymbolType type,
				const char *name,
				void *data,
				uint64_t address,
				uint64_t size);

		static SymbolFactory &instance();

	private:
		typedef std::list<ISymbolProvider *> SymbolProviders_t;

		SymbolFactory();

		SymbolProviders_t m_providers;
		ISymbolProvider *m_bestProvider;
	};
}
