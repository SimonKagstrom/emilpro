#pragma once

#include <list>
#include <vector>

#include "isymbol.hh"
#include "irelocation.hh"

namespace emilpro
{
	class ISymbolProvider;

	class ILineProvider;

	class ISymbolListener
	{
	public:
		virtual ~ISymbolListener()
		{
		}

		virtual void onSymbol(ISymbol &sym) = 0;
	};

	class IRelocationListener
	{
	public:
		virtual ~IRelocationListener()
		{
		}

		virtual void onRelocation(IRelocation &reloc) = 0;
	};

	class SymbolFactory
	{
	public:
		void destroy();

		void registerListener(ISymbolListener *listener, IRelocationListener *relocListener);

		void registerProvider(ISymbolProvider *provider);


		void registerLineProvider(ILineProvider *provider);

		ILineProvider *getLineProvider();

		unsigned parseBestProvider(void *data, size_t size);

		virtual ISymbol &createSymbol(enum ISymbol::LinkageType linkage,
				enum ISymbol::SymbolType type,
				const char *name,
				void *data,
				uint64_t address,
				uint64_t size,
				uint64_t fileOffset,
				bool isAllocated,
				bool isWriteable,
				bool isExecutable,
				unsigned int nr);

		virtual IRelocation &createRelocation(const ISymbol &symbol, uint64_t sourceAddress, size_t size, int64_t offset);

		static SymbolFactory &instance();

	private:
		class MetaListener : public ISymbolListener, public IRelocationListener
		{
		public:
			MetaListener(SymbolFactory &parent);

			void onSymbol(ISymbol &sym);

			void onRelocation(IRelocation &reloc);

		private:
			SymbolFactory &m_parent;
		};

		typedef std::list<ISymbolProvider *> SymbolProviders_t;
		typedef std::list<ISymbolListener *> SymbolListeners_t;
		typedef std::vector<IRelocationListener *> RelocationListeners_t;
		typedef std::list<ILineProvider *> LineProviders_t;
		typedef std::list<ISymbol *> Symbols_t;

		SymbolFactory();

		virtual ~SymbolFactory();

		SymbolProviders_t m_providers;
		SymbolListeners_t m_listeners;
		RelocationListeners_t m_relocationListeners;
		Symbols_t m_symbols;
		LineProviders_t m_lineProviders;

		MetaListener m_metaListener;
	};
}
