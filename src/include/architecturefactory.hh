#pragma once

#include <list>

#include <bfd.h>

namespace emilpro
{
	class ArchitectureFactory
	{
	public:
		typedef bfd_architecture Architecture_t;

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


