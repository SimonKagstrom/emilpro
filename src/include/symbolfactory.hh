#pragma once

#include <list>

namespace emilpro
{
	class ISymbolProvider;

	class ISymbolListener
	{
	public:
		virtual ~ISymbolListener()
		{
		}

		virtual void onSymbol(ISymbol &fn) = 0;
	};


	class SymbolFactory
	{
	public:
		void registerListener(ISymbolListener *listener);

		void registerProvider(ISymbolProvider *provider);

		static SymbolFactory &instance();

	private:
		typedef std::list<ISymbolProvider *> SymbolProviders_t;

		SymbolFactory();

		SymbolProviders_t m_providers;
		ISymbolProvider *m_bestProvider;
	};
}
