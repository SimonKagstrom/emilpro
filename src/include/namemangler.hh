#pragma once

#include <string>

#include <preferences.hh>

namespace emilpro
{
	class NameMangler : public Preferences::IListener
	{
	public:
		class IListener
		{
		public:
			virtual ~IListener()
			{
			}

			virtual void onManglingChanged(bool enabled) = 0;
		};

		void registerListener(IListener *);

		std::string mangle(const std::string &name);

		void destroy();

		static NameMangler &instance();

	private:
		virtual void onPreferencesChanged(const std::string &key,
				const std::string &oldValue, const std::string &newValue);

		NameMangler();

		~NameMangler();

		bool m_manglingEnabled;
		IListener *m_listener;
	};
}
