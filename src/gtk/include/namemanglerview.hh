#pragma once

#include <preferences.hh>
#include <namemangler.hh>

#include <gtkmm.h>

class NameManglerView : public emilpro::Preferences::IListener
{
public:
	class IListener
	{
	public:
		virtual ~IListener()
		{
		}

		virtual void onManglingChanged() = 0;
	};

	NameManglerView();

	void init(Glib::RefPtr<Gtk::Builder> builder);


	void registerListener(IListener *);

	std::string mangle(std::string name);

	static NameManglerView &instance();

private:
	void onMenuEntryActivated();

	virtual void onPreferencesChanged(const std::string &key,
			const std::string &oldValue, const std::string &newValue);

	emilpro::NameMangler &m_mangler;
	bool m_mangleNames;
	Gtk::CheckMenuItem *m_menuItem;

	IListener *m_listener;
};
