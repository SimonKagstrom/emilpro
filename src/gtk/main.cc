// FIXME! Refactor this file...

#include <gtkmm.h>
#include <gtksourceviewmm.h>

#include <model.hh>
#include <idisassembly.hh>
#include <architecturefactory.hh>
#include <configuration.hh>
#include <symbolfactory.hh>
#include <utils.hh>
#include <jumptargetdisplay.hh>
#include <hexview.hh>
#include <infobox.hh>
#include <symbolview.hh>
#include <instructionview.hh>
#include <sourceview.hh>
#include <emilpro.hh>
#include <server.hh>

#include <string>
#include <vector>

#include <emilpro_glade.hh>

using namespace emilpro;

class EmilProGui : public emilpro::Preferences::IListener
{
public:
	EmilProGui() :
		m_nLanes(4),
		m_data(NULL),
		m_dataSize(0),
		m_windowWidth(1024),
		m_windowHeight(768)
	{
	}

	~EmilProGui()
	{
	}

	void init(int argc, char **argv)
	{
		m_app = new Gtk::Main(argc, argv);
		Gsv::init();

		m_builder = Gtk::Builder::create_from_string(glade_file);

		m_hexView.init(m_builder);

		Gtk::ImageMenuItem *fileOpenItem;
		Gtk::ImageMenuItem *fileRefresh;
		Gtk::ImageMenuItem *fileQuit;
		Gtk::ImageMenuItem *viewForwardItem;
		Gtk::ImageMenuItem *viewBackwardItem;
		m_builder->get_widget("file_menu_open", fileOpenItem);
		m_builder->get_widget("file_menu_refresh", fileRefresh);
		m_builder->get_widget("file_menu_quit", fileQuit);
		m_builder->get_widget("view_menu_forward", viewForwardItem);
		m_builder->get_widget("view_menu_backward", viewBackwardItem);
		m_builder->get_widget("view_menu_mangle", m_viewMangleItem);
		m_builder->get_widget("view_x86_syntax", m_viewX86SyntaxItem);
		panic_if (!(fileOpenItem && viewForwardItem && viewBackwardItem),
				"Can't get menu items");
		fileOpenItem->signal_activate().connect(sigc::mem_fun(*this, &EmilProGui::onFileOpen));
		fileRefresh->signal_activate().connect(sigc::mem_fun(*this, &EmilProGui::onFileRefresh));
		fileQuit->signal_activate().connect(sigc::mem_fun(*this, &EmilProGui::onFileQuit));

		viewForwardItem->signal_activate().connect(sigc::mem_fun(*this, &EmilProGui::onViewForward));
		viewBackwardItem->signal_activate().connect(sigc::mem_fun(*this, &EmilProGui::onViewBackward));
		m_viewMangleItem->signal_activate().connect(sigc::mem_fun(*this, &EmilProGui::onViewMangle));
		m_viewX86SyntaxItem->signal_activate().connect(sigc::mem_fun(*this, &EmilProGui::onViewX86Syntax));

		// FIXME! Get this from properties instead!
		m_backgroundColor = Gdk::Color("white");


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
		Gtk::TextView &tvEnc = m_hexView.getEncodingTextView();

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
		tvEnc.override_font(Pango::FontDescription(sourceFont->get_font_name()));

		Gtk::ColorButton *historyColor;
		m_builder->get_widget("history_color2", historyColor);
		m_hexView.setMarkColor(historyColor->get_color());

		tv8.show();
		tv16.show();
		tv32.show();
		tv64.show();
		tvEnc.show();

		Gtk::Entry *lookupEntry;
		m_builder->get_widget("symbol_lookup_entry", lookupEntry);
		panic_if(!lookupEntry, "Can't get entry");

		lookupEntry->signal_activate().connect(sigc::mem_fun(*this,
				&EmilProGui::onEntryActivated));

		m_builder->get_widget("instructions_data_notebook", m_instructionsDataNotebook);
		panic_if(!m_instructionsDataNotebook, "Can't get notebook");

		Gtk::MenuItem *viewToggleInstructionsDataItem;
		m_builder->get_widget("view_toggle_instructions_data", viewToggleInstructionsDataItem);
		viewToggleInstructionsDataItem->signal_activate().connect(sigc::mem_fun(*this, &EmilProGui::onToggleInstructionsData));

		Gtk::MenuItem *viewFocusReferencesDataItem;
		m_builder->get_widget("view_focus_references", viewFocusReferencesDataItem);
		viewFocusReferencesDataItem->signal_activate().connect(sigc::mem_fun(*this, &EmilProGui::onFocusReferences));


		m_builder->get_widget("about_dialog", m_aboutDialog);
		panic_if(!m_aboutDialog,
				"No about dialog");

		Gtk::MenuItem *helpAboutMenuItem;
		m_builder->get_widget("menu_help_about", helpAboutMenuItem);
		helpAboutMenuItem->signal_activate().connect(sigc::mem_fun(*this, &EmilProGui::showAbout));

		m_infoBox.init(m_builder);
		m_sourceView.init(m_builder);
		m_instructionView.init(m_builder, &m_hexView, &m_infoBox, &m_sourceView, &m_symbolView, &m_addressHistory);
		m_symbolView.init(m_builder, &m_instructionView, &m_hexView, &m_addressHistory);

		m_builder->get_widget("instruction_view", m_instructionTreeView);
		panic_if(!m_instructionTreeView,
				"Can't get view");

		m_builder->get_widget("references_view", m_referencesTreeView);
		panic_if(!m_referencesTreeView,
				"Can't get view");

		m_builder->get_widget("main_window", m_window);
		Preferences::instance().registerListener("MainWindowSize", this);
		Preferences::instance().registerListener("X86InstructionSyntax", this);
	}

	void run()
	{
		std::string file = Configuration::instance().getFileName();

		if (file != "") {
			m_data = read_file(&m_dataSize, "%s", file.c_str());
			if (m_data) {
				Model::instance().addData(m_data, m_dataSize);
			} else {
				error("Can't read %s, exiting", file.c_str());
				exit(1);
			}

			refresh();
		}
		Server::instance().connect();

		m_app->run(*m_window);

		// Save preferences on quit
		updatePreferences();
	}

protected:

	void refresh()
	{
		Model::instance().registerSymbolListener(&m_symbolView);

		m_hexView.clearData();
		m_symbolView.refreshSymbols();
	}

	void onFileRefresh()
	{
		EmilPro::destroy();
		EmilPro::init();

		if (m_data) {
			if (!Model::instance().addData(m_data, m_dataSize))
				return;
		}

		m_instructionView.clear();
		m_sourceView.clear();
		refresh();
	}

	void onFileQuit()
	{
		m_windowWidth = m_window->get_width();
		m_windowHeight = m_window->get_height();

		Gtk::Main::quit();
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

		m_data = read_file(&m_dataSize, "%s", openFile->get_filename().c_str());

		if (!m_data)
			return; // FIXME! Do something

		EmilPro::destroy();
		EmilPro::init();

		if (!Model::instance().addData(m_data, m_dataSize))
			return;

		refresh();
	}

private:
	void onViewBackward()
	{
		updateHistoryEntry(m_addressHistory.back());
	}

	void onViewMangle()
	{
		bool isActive = m_viewMangleItem->get_active();

		std::string value = isActive ? "yes" : "no";

		Preferences::instance().setValue("MangleNames", value);
	}

	void onViewX86Syntax()
	{
		bool isActive = m_viewX86SyntaxItem->get_active();

		std::string value = isActive ? "att" : "intel";

		Preferences::instance().setValue("X86InstructionSyntax", value);

		if (m_data)
			onFileRefresh();
	}

	void onViewForward()
	{
		updateHistoryEntry(m_addressHistory.forward());
	}

	void updateHistoryEntry(const AddressHistory::Entry &e)
	{
		if (!e.isValid())
			return;

		m_instructionView.disableHistory();
		m_symbolView.update(e.getAddress());
		m_instructionView.enableHistory();

	}

	void onEntryActivated()
	{
		m_addressHistory.clear();
	}

	void showAbout()
	{
		m_aboutDialog->run();

		m_aboutDialog->hide();
	}

	void onToggleInstructionsData()
	{
		int page = 0;

		if (m_instructionTreeView->has_focus() ||
				m_hexView.getTextView(8).has_focus() ||
				m_hexView.getTextView(16).has_focus() ||
				m_hexView.getTextView(32).has_focus() ||
				m_hexView.getTextView(64).has_focus())
			page = !m_instructionsDataNotebook->get_current_page();

		m_instructionsDataNotebook->set_current_page(page);

		if (page == 0)
			m_instructionTreeView->grab_focus();
		else
			m_hexView.getTextView(8).grab_focus();
	}

	void onFocusReferences()
	{
		m_referencesTreeView->grab_focus();
	}

	void onPreferencesChanged(const std::string &key,
			const std::string &oldValue, const std::string &newValue)
	{
		if (key == "MainWindowSize") {
			size_t comma = newValue.find(",");
			// Malformed, fix it
			if (comma == std::string::npos) {
				updatePreferences();
				return;
			}

			std::string w = newValue.substr(0, comma);
			std::string h = newValue.substr(comma + 1, newValue.size());

			if (!string_is_integer(w) || !string_is_integer(h)) {
				updatePreferences();
				return;
			}
			if (string_to_integer(w) < 1024)
				w = "1024";
			if (string_to_integer(h) < 768)
				h = "768";

			m_windowWidth = (int)string_to_integer(w);
			m_windowHeight = (int)string_to_integer(h);

			printf("XXX: %d,%d\n", m_windowWidth, m_windowHeight);

			m_window->resize(m_windowWidth, m_windowHeight);
		} else if (key == "X86InstructionSyntax") {
			if (newValue == "intel")
				m_viewX86SyntaxItem->set_active(false);
			else
				m_viewX86SyntaxItem->set_active(true);
		}
	}

	void updatePreferences()
	{
		Preferences::instance().setValue("MainWindowSize",
				fmt("%d,%d", m_windowWidth, m_windowHeight));
	}


	typedef Gtk::TreeModel::Children TreeModelChildren_t;
	typedef std::list<Gtk::TreeModel::iterator> InstructionIterList_t;

	Gtk::Main *m_app;
	Glib::RefPtr<Gtk::Builder> m_builder;

	unsigned m_nLanes;

	Gdk::Color m_historyColors[3];
	Gdk::Color m_backgroundColor;

	HexView m_hexView;
	InfoBox m_infoBox;
	InstructionView m_instructionView;
	SymbolView m_symbolView;
	SourceView m_sourceView;
	AddressHistory m_addressHistory;
	Gtk::TreeView *m_instructionTreeView;
	Gtk::Notebook *m_instructionsDataNotebook;
	Gtk::TreeView *m_referencesTreeView;
	Gtk::Window *m_window;
	Gtk::AboutDialog *m_aboutDialog;
	Gtk::CheckMenuItem *m_viewMangleItem;
	Gtk::CheckMenuItem *m_viewX86SyntaxItem;

	void *m_data;
	size_t m_dataSize;

	int m_windowWidth;
	int m_windowHeight;
};

int main(int argc, char **argv)
{
	EmilPro::init();

	Configuration &conf = Configuration::instance();

	if (conf.parse(argc, (const char **)argv) != true)
		return 1;

	if ((conf.getDebugLevel() & Configuration::DBG_ERRORS) == 0)
		fclose(stderr);

	EmilProGui *gui = new EmilProGui();

	gui->init(argc, argv);

	gui->run();

	delete gui;

	EmilPro::destroy();

	return 0;
}
