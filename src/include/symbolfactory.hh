#pragma once

#include <list>

#include "isymbol.hh"

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
		void destroy();

		void registerListener(ISymbolListener *listener);

		void registerProvider(ISymbolProvider *provider);


		unsigned parseBestProvider(void *data, size_t size);

		virtual ISymbol &createSymbol(enum ISymbol::LinkageType linkage,
				enum ISymbol::SymbolType type,
				const char *name,
				void *data,
				uint64_t address,
				uint64_t size,
				bool isAllocated,
				bool isWriteable);

		static SymbolFactory &instance();

	private:
		class MetaListener : public ISymbolListener
		{
		public:
			MetaListener(SymbolFactory &parent);

			void onSymbol(ISymbol &sym);

		private:
			SymbolFactory &m_parent;
		};

		typedef std::list<ISymbolProvider *> SymbolProviders_t;
		typedef std::list<ISymbolListener *> SymbolListeners_t;
		typedef std::list<ISymbol *> Symbols_t;

		SymbolFactory();

		virtual ~SymbolFactory();

		SymbolProviders_t m_providers;
		SymbolListeners_t m_listeners;
		Symbols_t m_symbols;

		MetaListener m_metaListener;
	};
}
