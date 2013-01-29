#include <gtkmm.h>

#include <model.hh>
#include <idisassembly.hh>
#include <architecturefactory.hh>
#include <symbolfactory.hh>
#include <utils.hh>
#include <jumptargetdisplay.hh>

#include <string>

using namespace emilpro;

class SymbolModelColumns : public Gtk::TreeModelColumnRecord
{
public:
	SymbolModelColumns()
	{
		add(m_pixbuf);
		add(m_address);
		add(m_size);
		add(m_name);
	}

	Gtk::TreeModelColumn<Glib::RefPtr<Gdk::Pixbuf>> m_pixbuf;
	Gtk::TreeModelColumn<Glib::ustring> m_address;
	Gtk::TreeModelColumn<Glib::ustring> m_size;
	Gtk::TreeModelColumn<Glib::ustring> m_name;
};

class InstructionModelColumns : public Gtk::TreeModelColumnRecord
{
public:
	InstructionModelColumns()
	{
		add(m_address);
		add(m_backward);
		add(m_instruction);
		add(m_forward);
		add(m_target);
	}

	Gtk::TreeModelColumn<Glib::ustring> m_address;
	Gtk::TreeModelColumn<JumpTargetDisplay::LaneValue_t> m_backward;
	Gtk::TreeModelColumn<Glib::ustring> m_instruction;
	Gtk::TreeModelColumn<JumpTargetDisplay::LaneValue_t> m_forward;
	Gtk::TreeModelColumn<Glib::ustring> m_target;
};

class EmilProGui
{
public:
	EmilProGui()
	{
		m_backwardBranches = new JumpTargetDisplay(false, 4);
		m_forwardBranches = new JumpTargetDisplay(false, 4);
	}

	~EmilProGui()
	{
		delete m_symbolColumns;
		delete m_instructionColumns;
		delete m_forwardBranches;
		delete m_backwardBranches;
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

		m_instructionListStore = Glib::RefPtr<Gtk::ListStore>::cast_static(m_builder->get_object("instruction_liststore"));
		panic_if (!m_instructionListStore,
				"Can't get instruction liststore");

		m_symbolColumns = new SymbolModelColumns();
		m_instructionColumns = new InstructionModelColumns();

		m_builder->get_widget("instruction_view", m_instructionView);
		panic_if(!m_instructionView,
				"Can't get symbol view");

		setFont(Glib::RefPtr<Gtk::CellRendererText>::cast_static(m_builder->get_object("symbol_view_address_text")));
		setFont(Glib::RefPtr<Gtk::CellRendererText>::cast_static(m_builder->get_object("symbol_view_size_text")));
		setFont(Glib::RefPtr<Gtk::CellRendererText>::cast_static(m_builder->get_object("symbol_view_symbol_text")));
		setFont(Glib::RefPtr<Gtk::CellRendererText>::cast_static(m_builder->get_object("instruction_view_address_text")));
		setFont(Glib::RefPtr<Gtk::CellRendererText>::cast_static(m_builder->get_object("instruction_view_instruction_text")));
		setFont(Glib::RefPtr<Gtk::CellRendererText>::cast_static(m_builder->get_object("instruction_view_target_text")));

		Gtk::TreeView *symbolView;
		m_builder->get_widget("symbol_view", symbolView);
		panic_if(!symbolView,
				"Can't get symbol view");

		symbolView->signal_row_activated().connect(sigc::mem_fun(*this,
				&EmilProGui::onSymbolRowActivated));
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
	void setFont(Glib::RefPtr<Gtk::CellRendererText> renderer)
	{
		panic_if(!renderer,
				"Can't get renderer");

		renderer->property_font() = "Monospace";
	}

	void onSymbolRowActivated(const Gtk::TreeModel::Path& path, Gtk::TreeViewColumn* column)
	{
		Gtk::TreeModel::iterator iter = m_symbolListStore->get_iter(path);

		if(!iter)
			return;
		Model &model = Model::instance();

		Gtk::TreeModel::Row row = *iter;
		// FIXME! Should really be a uint64_t...
		Glib::ustring address = row[m_symbolColumns->m_address];

		const ISymbol *sym = model.getSymbol(strtoull(address.c_str(), NULL, 16));
		if (!sym) {
			warning("Can't get symbol\n");
			return;
		}

		if (sym->getType() != ISymbol::SYM_TEXT) {
			warning("Only code for now\n");
			return;
		}
		m_instructionListStore->clear();

		// Disassemble and display
		InstructionList_t insns = model.getInstructions(sym->getAddress(), sym->getAddress() + sym->getSize());
		for (InstructionList_t::iterator it = insns.begin();
				it != insns.end();
				++it) {
			IInstruction *cur = *it;

			Gtk::ListStore::iterator rowIt = m_instructionListStore->append();
			Gtk::TreeRow row = *rowIt;

			row[m_instructionColumns->m_address] = fmt("0x%0llx", cur->getAddress()).c_str();
			row[m_instructionColumns->m_instruction] = cur->getString();
			if (cur->getBranchTargetAddress() != 0) {
				uint64_t target = cur->getBranchTargetAddress();
				const ISymbol *targetSym = model.getSymbol(target);

				if (!targetSym || (target >= sym->getAddress() && target < sym->getAddress() + sym->getSize()))
					row[m_instructionColumns->m_target] = fmt("0x%0llx", cur->getBranchTargetAddress()).c_str();
				else
					row[m_instructionColumns->m_target] = targetSym->getName();
			}
		}
	}

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
			row[m_symbolColumns->m_size] = fmt("0x%08llx", cur->getSize()).c_str();
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
	Glib::RefPtr<Gtk::ListStore> m_instructionListStore;
	SymbolModelColumns *m_symbolColumns;
	InstructionModelColumns *m_instructionColumns;
	Gtk::TreeView *m_instructionView;

	JumpTargetDisplay *m_backwardBranches;
	JumpTargetDisplay *m_forwardBranches;
};

int main(int argc, char **argv)
{
	EmilProGui gui;

	gui.init(argc, argv);

	gui.run(argc, argv);

	return 0;
}
