#include <gtkmm.h>

#include <model.hh>
#include <idisassembly.hh>
#include <architecturefactory.hh>
#include <symbolfactory.hh>
#include <utils.hh>

#include <string>

using namespace emilpro;

class SymbolModelColumns : public Gtk::TreeModelColumnRecord
{
public:
	SymbolModelColumns()
	{
		add(m_pixbuf);
		add(m_address);
		add(m_name);
	}

	Gtk::TreeModelColumn<Glib::RefPtr<Gdk::Pixbuf>> m_pixbuf;
	Gtk::TreeModelColumn<Glib::ustring> m_address;
	Gtk::TreeModelColumn<Glib::ustring> m_name;
};


class EmilProGui
{
public:
	EmilProGui()
	{
	}

	~EmilProGui()
	{
		delete m_symbolColumns;
	}

	void init(int argc, char **argv)
	{
		m_app = new Gtk::Main(argc, argv);

		m_builder = Gtk::Builder::create_from_file("/home/ska/projects/emilpro/src/gtk/emilpro.glade");

		Gtk::ImageMenuItem *fileOpenItem;
		m_builder->get_widget("file_menu_open", fileOpenItem);

		panic_if (!fileOpenItem,
				"Can't get file_menu_open");
		fileOpenItem->signal_activate().connect(sigc::mem_fun(*this, &EmilProGui::onFileOpen));

		m_symbolListStore = Glib::RefPtr<Gtk::ListStore>::cast_static(m_builder->get_object("symbol_liststore"));
		panic_if (!m_symbolListStore,
				"Can't get symbol liststore");

		m_symbolColumns = new SymbolModelColumns();

		Glib::RefPtr<Gtk::CellRendererText> symbolAddressRenderer = Glib::RefPtr<Gtk::CellRendererText>::cast_static(m_builder->get_object("symbol_view_address_text"));
		panic_if(!symbolAddressRenderer,
				"Can't get symbol address renderer");
		Glib::RefPtr<Gtk::CellRendererText> symbolTextRenderer = Glib::RefPtr<Gtk::CellRendererText>::cast_static(m_builder->get_object("symbol_view_symbol_text"));
		panic_if(!symbolTextRenderer,
				"Can't get symbol text renderer");

		symbolAddressRenderer->property_font() = "Monospace";
		symbolTextRenderer->property_font() = "Monospace";
	}

	void run(int argc, char *argv[])
	{
		if (argc > 1) {
			const char *file = argv[1];
			void *data;
			size_t sz;

			data = read_file(&sz, "%s", file);
			if (data) {
				Model::instance().addData(data, sz);
			}

			refresh();
		}

		Gtk::Window * mainWindow = NULL;
		m_builder->get_widget("main_window", mainWindow);

		m_app->run(*mainWindow);
	}

protected:
	void refresh()
	{
		m_symbolListStore->clear();

		const Model::SymbolList_t &syms = Model::instance().getSymbols();

		for (Model::SymbolList_t::const_iterator it = syms.begin();
				it != syms.end();
				++it) {
			ISymbol *cur = *it;

			Gtk::ListStore::iterator rowIt = m_symbolListStore->append();
			Gtk::TreeRow row = *rowIt;

			row[m_symbolColumns->m_address] = fmt("0x%llx", cur->getAddress()).c_str();
			row[m_symbolColumns->m_name] = cur->getName();
		}
	}

	void onFileOpen()
	{
		Gtk::FileChooserDialog *openFile = NULL;
		m_builder->get_widget("file_chooser", openFile);

		panic_if (!openFile,
				"Open file dialogue does not exist");

		int v = openFile->run();

		openFile->hide();

		if (v != Gtk::RESPONSE_ACCEPT)
			return;

		size_t sz;

		void *data = read_file(&sz, "%s", openFile->get_filename().c_str());

		if (!data)
			return; // FIXME! Do something

		Model::instance().destroy();
		SymbolFactory::instance().destroy();
		IDisassembly::instance().destroy();
		ArchitectureFactory::instance().destroy();

		if (!Model::instance().addData(data, sz))
			return;

		refresh();
	}

private:
	 typedef Gtk::TreeModel::Children TreeModelChildren_t;

	Gtk::Main *m_app;
	Glib::RefPtr<Gtk::Builder> m_builder;
	Glib::RefPtr<Gtk::ListStore> m_symbolListStore;
	SymbolModelColumns *m_symbolColumns;
};

int main(int argc, char **argv)
{
	EmilProGui gui;

	gui.init(argc, argv);

	gui.run(argc, argv);

	return 0;
}
