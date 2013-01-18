#include <gtkmm.h>

#include <model.hh>
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
	Gtk::TreeModelColumn<uint64_t> m_address;
	Gtk::TreeModelColumn<Glib::ustring> m_name;
};


class EmilProGui
{
public:
	EmilProGui()
	{
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

	}

	void run()
	{
		Gtk::Window * mainWindow = NULL;
		m_builder->get_widget("main_window", mainWindow);

		m_app->run(*mainWindow);
	}

protected:
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

		if (!Model::instance().addData(data, sz))
			return;

		SymbolModelColumns columns;

		const Model::SymbolList_t &syms = Model::instance().getSymbols();

		for (Model::SymbolList_t::const_iterator it = syms.begin();
				it != syms.end();
				++it) {
			ISymbol *cur = *it;

			Gtk::ListStore::iterator row = m_symbolListStore->append();

			(*row)[columns.m_address] = cur->getAddress();
			(*row)[columns.m_name] = cur->getName();
		}
	}

private:
	 typedef Gtk::TreeModel::Children TreeModelChildren_t;

	Gtk::Main *m_app;
	Glib::RefPtr<Gtk::Builder> m_builder;
	Glib::RefPtr<Gtk::ListStore> m_symbolListStore;
};

int main(int argc, char **argv)
{
	EmilProGui gui;

	gui.init(argc, argv);

	gui.run();

	return 0;
}
