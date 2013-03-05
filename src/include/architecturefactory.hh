#pragma once

#include <list>
#include <unordered_map>
#include <string>

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

		virtual std::string &getNameFromArchitecture(Architecture_t arch);

		virtual Architecture_t getArchitectureFromName(std::string name);

		virtual void registerListener(IArchitectureListener *listener);

		virtual void provideArchitecture(Architecture_t arch);

		static ArchitectureFactory &instance();

	private:
		typedef std::list<IArchitectureListener *> ArchitectureListeners_t;
		typedef std::unordered_map<unsigned, std::string> ArchitectureNameMap_t;
		typedef std::unordered_map<std::string, unsigned> NameArchitectureMap_t;

		ArchitectureFactory();

		virtual ~ArchitectureFactory();

		ArchitectureListeners_t m_listeners;
		Architecture_t m_architecture;
		ArchitectureNameMap_t m_architectureNameMap;
		NameArchitectureMap_t m_nameArchitectureMap;

		std::string m_unknownArchitecture;
	};
}


