#include <utils.hh>

#include <namemanglerview.hh>

using namespace emilpro;

NameManglerView::NameManglerView() :
	m_mangler(NameMangler::instance()),
	m_mangleNames(true),
	m_menuItem(NULL),
	m_listener(NULL)
{
	Preferences::instance().registerListener("MangleNames", this);
}

void NameManglerView::init(Glib::RefPtr<Gtk::Builder> builder)
{
	builder->get_widget("view_menu_mangle", m_menuItem);
	panic_if(!m_menuItem, "Can't get menu item");

	m_menuItem->signal_activate().connect(sigc::mem_fun(*this,
			&NameManglerView::onMenuEntryActivated));

	m_menuItem->set_active(m_mangleNames);
}

std::string NameManglerView::mangle(std::string name)
{
	if (!m_mangleNames)
		return name;

	return m_mangler.mangle(name);
}

static NameManglerView *g_instance;
NameManglerView& NameManglerView::instance()
{
	if (!g_instance)
		g_instance = new NameManglerView();

	return *g_instance;
}

void NameManglerView::onMenuEntryActivated()
{
	bool isActive = m_menuItem->get_active();
	bool old = m_mangleNames;

	m_mangleNames = isActive;

	if (isActive == old)
		return;

	std::string value = isActive ? "yes" : "no";

	Preferences::instance().setValue("MangleNames", value);

	if (m_listener)
		m_listener->onManglingChanged();
}

void NameManglerView::onPreferencesChanged(const std::string& key,
		const std::string& oldValue, const std::string& newValue)
{
	if (key != "MangleNames")
		return;

	if (newValue == "yes")
		m_mangleNames = true;
	else
		m_mangleNames = false;
}

void NameManglerView::registerListener(IListener *p)
{
	panic_if(m_listener,
			"Only one for now");

	m_listener = p;
}
