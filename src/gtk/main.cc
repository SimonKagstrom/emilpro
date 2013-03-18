// FIXME! Refactor this file...

#include <gtkmm.h>
#include <gtksourceviewmm.h>

#include <model.hh>
#include <idisassembly.hh>
#include <architecturefactory.hh>
#include <symbolfactory.hh>
#include <utils.hh>
#include <jumptargetdisplay.hh>
#include <hexview.hh>
#include <infobox.hh>
#include <instructionview.hh>
#include <sourceview.hh>
#include <emilpro.hh>

#include <string>
#include <vector>

#include <emilpro_glade.hh>

using namespace emilpro;



class SymbolModelColumns : public Gtk::TreeModelColumnRecord
{
public:
	SymbolModelColumns()
	{
		add(m_address);
		add(m_size);
		add(m_r);
		add(m_w);
		add(m_x);
		add(m_a);
		add(m_name);

		add(m_rawAddress);
		add(m_bgColor);
	}

	unsigned getNumberOfVisibleColumns()
	{
		return 7;
	}

	Gtk::TreeModelColumn<Glib::ustring> m_address;
	Gtk::TreeModelColumn<Glib::ustring> m_size;
	Gtk::TreeModelColumn<Glib::ustring> m_r;
	Gtk::TreeModelColumn<Glib::ustring> m_w;
	Gtk::TreeModelColumn<Glib::ustring> m_x;
	Gtk::TreeModelColumn<Glib::ustring> m_a;
	Gtk::TreeModelColumn<Glib::ustring> m_name;

	// Hidden
	Gtk::TreeModelColumn<uint64_t> m_rawAddress;
	Gtk::TreeModelColumn<Gdk::Color> m_bgColor;
};

class ReferenceModelColumns : public Gtk::TreeModelColumnRecord
{
public:
	ReferenceModelColumns()
	{
		add(m_symbol);

		add(m_rawAddress);
	}

	Gtk::TreeModelColumn<Glib::ustring> m_symbol;

	// Hidden
	Gtk::TreeModelColumn<uint64_t> m_rawAddress;
};


class EmilProGui
{
public:
	EmilProGui() :
		m_nLanes(4)
	{
	}

	~EmilProGui()
	{
		delete m_symbolColumns;
		delete m_referenceColumns;
	}

	void init(int argc, char **argv)
	{
		m_app = new Gtk::Main(argc, argv);
		Gsv::init();

		m_hexView.init();

		m_builder = Gtk::Builder::create_from_string(glade_file);

		Gtk::ImageMenuItem *fileOpenItem;
		m_builder->get_widget("file_menu_open", fileOpenItem);

		panic_if (!fileOpenItem,
				"Can't get file_menu_open");
		fileOpenItem->signal_activate().connect(sigc::mem_fun(*this, &EmilProGui::onFileOpen));

		m_symbolColumns = new SymbolModelColumns();
		m_referenceColumns = new ReferenceModelColumns();

		Gtk::FontButton *symbolFont;
		m_builder->get_widget("symbol_font", symbolFont);
		panic_if(!symbolFont,
				"Can't get instruction view");

		m_builder->get_widget("symbol_view", m_symbolView);
		panic_if(!m_symbolView,
				"Can't get symbol view");
		m_symbolView->override_font(Pango::FontDescription(symbolFont->get_font_name()));

		m_symbolListStore = Gtk::ListStore::create(*m_symbolColumns);
		m_symbolView->append_column("Address", m_symbolColumns->m_address);
		m_symbolView->append_column("Size", m_symbolColumns->m_size);
		m_symbolView->append_column("R", m_symbolColumns->m_r);
		m_symbolView->append_column("W", m_symbolColumns->m_w);
		m_symbolView->append_column("X", m_symbolColumns->m_x);
		m_symbolView->append_column("A", m_symbolColumns->m_a);
		m_symbolView->append_column("SymbolName", m_symbolColumns->m_name);

		m_symbolView->set_model(m_symbolListStore);

		m_symbolView->signal_row_activated().connect(sigc::mem_fun(*this,
				&EmilProGui::onSymbolRowActivated));
		m_symbolView->signal_cursor_changed().connect(sigc::mem_fun(*this,
				&EmilProGui::onSymbolCursorChanged));

		// FIXME! Get this from properties instead!
		m_backgroundColor = Gdk::Color("white");
		for (unsigned i = 0; i < m_symbolColumns->getNumberOfVisibleColumns(); i++) {
			Gtk::TreeViewColumn *cp;
			Gtk::CellRenderer *cr;

			cp = m_symbolView->get_column(i);

			cr = cp->get_first_cell();

			cp->add_attribute(cr->property_cell_background_gdk(), m_symbolColumns->m_bgColor);
		}

		m_builder->get_widget("references_view", m_referencesView);
		panic_if(!m_referencesView,
				"Can't get reference view");

		m_referencesListStore = Gtk::ListStore::create(*m_referenceColumns);
		m_referencesView->append_column("Symbol references", m_referenceColumns->m_symbol);

		m_referencesView->set_model(m_referencesListStore);

		Gtk::FontButton *referencesFont;
		m_builder->get_widget("references_font", referencesFont);
		panic_if(!referencesFont,
				"Can't get references font");

		m_referencesView->override_font(Pango::FontDescription(referencesFont->get_font_name()));

		m_referencesView->signal_row_activated().connect(sigc::mem_fun(*this,
				&EmilProGui::onReferenceRowActivated));


		Gtk::ScrolledWindow *hexView8Bit, *hexView16Bit, *hexView32Bit, *hexView64Bit;
		m_builder->get_widget("hex_data_8bit_scrolledwindow", hexView8Bit);
		m_builder->get_widget("hex_data_16bit_scrolledwindow", hexView16Bit);
		m_builder->get_widget("hex_data_32bit_scrolledwindow", hexView32Bit);
		m_builder->get_widget("hex_data_64bit_scrolledwindow", hexView64Bit);

		panic_if(!hexView64Bit, "Can't get hexview");

		Gtk::TextView &tv8 = m_hexView.getTextView(8);
		Gtk::TextView &tv16 = m_hexView.getTextView(16);
		Gtk::TextView &tv32 = m_hexView.getTextView(32);
		Gtk::TextView &tv64 = m_hexView.getTextView(64);

		hexView8Bit->add(tv8);
		hexView16Bit->add(tv16);
		hexView32Bit->add(tv32);
		hexView64Bit->add(tv64);

		Gtk::FontButton *sourceFont;
		m_builder->get_widget("source_font", sourceFont);
		panic_if(!sourceFont,
				"Can't get source font");

		tv8.override_font(Pango::FontDescription(sourceFont->get_font_name()));
		tv16.override_font(Pango::FontDescription(sourceFont->get_font_name()));
		tv32.override_font(Pango::FontDescription(sourceFont->get_font_name()));
		tv64.override_font(Pango::FontDescription(sourceFont->get_font_name()));

		Gtk::ColorButton *historyColor;
		m_builder->get_widget("history_color2", historyColor);
		m_hexView.setMarkColor(historyColor->get_color());

		tv8.show();
		tv16.show();
		tv32.show();
		tv64.show();

		m_builder->get_widget("instructions_data_notebook", m_instructionsDataNotebook);
		panic_if(!m_instructionsDataNotebook, "Can't get notebook");

		m_infoBox.init(m_builder);
		m_sourceView.init(m_builder);
		m_instructionView.init(m_builder, &m_hexView, &m_infoBox, &m_sourceView);
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

	void onSymbolCursorChanged()
	{
		Gtk::TreeModel::Path path;
		Gtk::TreeViewColumn *column;

		m_symbolView->get_cursor(path, column);

		Gtk::TreeModel::iterator iter = m_symbolListStore->get_iter(path);

		m_referencesListStore->clear();

		if(!iter)
			return;
		Model &model = Model::instance();

		Gtk::TreeModel::Row row = *iter;
		uint64_t address = row[m_symbolColumns->m_rawAddress];

		const Model::CrossReferenceList_t &references = model.getReferences(address);

		for (Model::CrossReferenceList_t::const_iterator it = references.begin();
				it != references.end();
				++it) {
			uint64_t cur = *it;
			const Model::SymbolList_t syms = model.getNearestSymbol(cur);

			Gtk::ListStore::iterator rowIt = m_referencesListStore->append();
			Gtk::TreeRow row = *rowIt;

			if (syms.empty()) {
				row[m_referenceColumns->m_symbol] = fmt("0x%llx", (long long)cur);
				row[m_referenceColumns->m_rawAddress] = IInstruction::INVALID_ADDRESS;
			} else {
				for (Model::SymbolList_t::const_iterator sIt = syms.begin();
						sIt != syms.end();
						++sIt) {
					ISymbol *sym = *sIt;

					row[m_referenceColumns->m_symbol] = fmt("%s+0x%llx", sym->getName(), (long long)(cur - sym->getAddress()));
					row[m_referenceColumns->m_rawAddress] = cur;
				}
			}
		}
	}

	void onSymbolRowActivated(const Gtk::TreeModel::Path& path, Gtk::TreeViewColumn* column)
	{
		Gtk::TreeModel::iterator iter = m_symbolListStore->get_iter(path);

		if(!iter)
			return;

		Model &model = Model::instance();

		Gtk::TreeModel::Row row = *iter;
		uint64_t address = row[m_symbolColumns->m_rawAddress];

		Model::SymbolList_t syms = model.getSymbolExact(address);
		if (syms.empty()) {
			warning("Can't get symbol\n");
			return;
		}

		const ISymbol *largest = syms.front();

		for (Model::SymbolList_t::iterator it = syms.begin();
				it != syms.end();
				++it) {
			const ISymbol *cur = *it;
			enum ISymbol::SymbolType type = cur->getType();

			if (type != ISymbol::SYM_TEXT && type != ISymbol::SYM_DATA)
				continue;

			if (largest->getType() != ISymbol::SYM_TEXT && largest->getType() != ISymbol::SYM_DATA)
				largest = cur;

			if (cur->getSize() > largest->getSize())
				largest = cur;
		}

		if (largest->getType() == ISymbol::SYM_TEXT)
			m_instructionView.update(address, *largest);
		else
			updateDataView(address, largest);
	}

	void onReferenceRowActivated(const Gtk::TreeModel::Path& path, Gtk::TreeViewColumn* column)
	{
		Gtk::TreeModel::iterator iter = m_referencesListStore->get_iter(path);

		if(!iter)
			return;

		Model &model = Model::instance();

		Gtk::TreeModel::Row row = *iter;
		uint64_t address = row[m_referenceColumns->m_rawAddress];

		if (address == IInstruction::INVALID_ADDRESS)
			return;

		Model::SymbolList_t syms = model.getNearestSymbol(address);
		if (syms.empty()) {
			warning("Can't get symbol\n");
			return;
		}

		const ISymbol *largest = syms.front();

		for (Model::SymbolList_t::iterator it = syms.begin();
				it != syms.end();
				++it) {
			const ISymbol *cur = *it;
			enum ISymbol::SymbolType type = cur->getType();

			if (type != ISymbol::SYM_TEXT && type != ISymbol::SYM_DATA)
				continue;

			if (largest->getType() != ISymbol::SYM_TEXT && largest->getType() != ISymbol::SYM_DATA)
				largest = cur;

			if (cur->getSize() > largest->getSize())
				largest = cur;
		}

		if (largest->getType() == ISymbol::SYM_TEXT)
			updateSourceView(address, largest);
		else
			updateDataView(address, largest);
	}

	void updateSourceView(uint64_t address, const ISymbol *sym)
	{
		m_instructionsDataNotebook->set_current_page(0);

		m_instructionView.update(address, *sym);
	}

	void updateDataView(uint64_t address, const ISymbol *sym)
	{
		m_instructionsDataNotebook->set_current_page(1);

		m_hexView.markRange(sym->getAddress(), (size_t)sym->getSize());
	}

	void refresh()
	{
		Model::instance().parseAll();

		m_symbolListStore->clear();
		m_hexView.clearData();

		const Model::SymbolList_t &syms = Model::instance().getSymbols();

		for (Model::SymbolList_t::const_iterator it = syms.begin();
				it != syms.end();
				++it) {
			ISymbol *cur = *it;

			// Skip the file symbol
			if (cur->getType() == ISymbol::SYM_FILE)
				continue;

			if (cur->getType() == ISymbol::SYM_SECTION
					&& cur->getSize() > 0)
				m_hexView.addData(cur->getDataPtr(), cur->getAddress(), cur->getSize());

			Gtk::ListStore::iterator rowIt = m_symbolListStore->append();
			Gtk::TreeRow row = *rowIt;

			const char *r = " ";
			const char *w = cur->isWriteable() ? "W" : " ";
			const char *x = " ";
			const char *a = cur->isAllocated() ? "A" : " ";

			ISymbol::SymbolType type = cur->getType();
			if (type == ISymbol::SYM_TEXT) {
				r = "R";
				x = "X";
				w = " ";
			} else if (type == ISymbol::SYM_DATA) {
				r = "R";
			}

			row[m_symbolColumns->m_address] = fmt("0x%llx", (long long)cur->getAddress()).c_str();
			row[m_symbolColumns->m_size] = fmt("0x%08llx", (long long)cur->getSize()).c_str();
			row[m_symbolColumns->m_r] = r;
			row[m_symbolColumns->m_w] = w;
			row[m_symbolColumns->m_x] = x;
			row[m_symbolColumns->m_a] = a;
			row[m_symbolColumns->m_name] = fmt("%s%s",
					cur->getType() == ISymbol::SYM_SECTION ? "Section " : "", cur->getName());

			row[m_symbolColumns->m_rawAddress] = cur->getAddress();
		}

		m_hexView.update();
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
	typedef std::list<Gtk::TreeModel::iterator> InstructionIterList_t;

	Gtk::Main *m_app;
	Glib::RefPtr<Gtk::Builder> m_builder;
	Glib::RefPtr<Gtk::ListStore> m_symbolListStore;
	Glib::RefPtr<Gtk::ListStore> m_referencesListStore;
	SymbolModelColumns *m_symbolColumns;
	ReferenceModelColumns *m_referenceColumns;
	Gtk::TreeView *m_symbolView;
	Gtk::TreeView *m_referencesView;

	unsigned m_nLanes;

	Gdk::Color m_historyColors[3];
	Gdk::Color m_backgroundColor;

	HexView m_hexView;
	InfoBox m_infoBox;
	InstructionView m_instructionView;
	SourceView m_sourceView;

	Gtk::Notebook *m_instructionsDataNotebook;
};

int main(int argc, char **argv)
{
	EmilPro::init();

	EmilProGui gui;

	gui.init(argc, argv);

	gui.run(argc, argv);

	EmilPro::destroy();

	return 0;
}
