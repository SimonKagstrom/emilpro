#include <gtkmm.h>
#include <gtksourceviewmm.h>

#include <model.hh>
#include <idisassembly.hh>
#include <architecturefactory.hh>
#include <symbolfactory.hh>
#include <utils.hh>
#include <jumptargetdisplay.hh>

#include <string>
#include <vector>

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
	}

	Gtk::TreeModelColumn<Glib::ustring> m_address;
	Gtk::TreeModelColumn<Glib::ustring> m_size;
	Gtk::TreeModelColumn<Glib::ustring> m_r;
	Gtk::TreeModelColumn<Glib::ustring> m_w;
	Gtk::TreeModelColumn<Glib::ustring> m_x;
	Gtk::TreeModelColumn<Glib::ustring> m_a;
	Gtk::TreeModelColumn<Glib::ustring> m_name;
};

class InstructionModelColumns : public Gtk::TreeModelColumnRecord
{
public:
	InstructionModelColumns(unsigned nLanes)
	{
		m_backward = new Gtk::TreeModelColumn<Glib::RefPtr<Gdk::Pixbuf>>[nLanes];
		m_forward= new Gtk::TreeModelColumn<Glib::RefPtr<Gdk::Pixbuf>>[nLanes];

		add(m_address);
		for (unsigned i = 0; i < nLanes; i++)
			add(m_backward[i]);
		add(m_instruction);
		for (unsigned i = 0; i < nLanes; i++)
			add(m_forward[i]);
		add(m_target);
	}

	~InstructionModelColumns()
	{
		delete[] m_backward;
		delete[] m_forward;
	}

	Gtk::TreeModelColumn<Glib::ustring> m_address;
	Gtk::TreeModelColumn<Glib::RefPtr<Gdk::Pixbuf>> *m_backward;
	Gtk::TreeModelColumn<Glib::ustring> m_instruction;
	Gtk::TreeModelColumn<Glib::RefPtr<Gdk::Pixbuf>> *m_forward;
	Gtk::TreeModelColumn<Glib::ustring> m_target;
};

class EmilProGui
{
public:
	EmilProGui() : m_nLanes(4), m_fontHeight(20) // FIXME!
	{
		m_backwardBranches = new JumpTargetDisplay(false, m_nLanes);
		m_forwardBranches = new JumpTargetDisplay(true, m_nLanes);
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
		Gsv::init();

		m_pixbufs[JumpTargetDisplay::LANE_LINE] = Gdk::Pixbuf::create_from_file("../../../emilpro/gfx/red_line.png");
		m_pixbufs[JumpTargetDisplay::LANE_START_DOWN] = Gdk::Pixbuf::create_from_file("../../../emilpro/gfx/red_start_down.png");
		m_pixbufs[JumpTargetDisplay::LANE_START_UP] = Gdk::Pixbuf::create_from_file("../../../emilpro/gfx/red_start_up.png");
		m_pixbufs[JumpTargetDisplay::LANE_START_LONG_UP] = Gdk::Pixbuf::create_from_file("../../../emilpro/gfx/red_long_start.png");
		m_pixbufs[JumpTargetDisplay::LANE_START_LONG_DOWN] = Gdk::Pixbuf::create_from_file("../../../emilpro/gfx/red_long_start.png");
		m_pixbufs[JumpTargetDisplay::LANE_END_DOWN] = Gdk::Pixbuf::create_from_file("../../../emilpro/gfx/red_arrow_left.png");
		m_pixbufs[JumpTargetDisplay::LANE_END_UP] = Gdk::Pixbuf::create_from_file("../../../emilpro/gfx/red_arrow_right.png");
		m_pixbufs[JumpTargetDisplay::LANE_END_LONG_DOWN] = Gdk::Pixbuf::create_from_file("../../../emilpro/gfx/red_long_end.png");
		m_pixbufs[JumpTargetDisplay::LANE_END_LONG_UP] = Gdk::Pixbuf::create_from_file("../../../emilpro/gfx/red_long_start.png");

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
		m_instructionColumns = new InstructionModelColumns(m_nLanes);

		m_instructionListStore = Gtk::ListStore::create(*m_instructionColumns);
		panic_if (!m_instructionListStore,
				"Can't get instruction liststore");

		m_builder->get_widget("instruction_view", m_instructionView);
		panic_if(!m_instructionView,
				"Can't get instruction view");


		Gtk::FontButton *instructionFont;
		m_builder->get_widget("instruction_font", instructionFont);
		panic_if(!instructionFont,
				"Can't get instruction font");

		m_instructionView->override_font(Pango::FontDescription(instructionFont->get_font_name()));

		m_instructionView->set_model(m_instructionListStore);

		m_instructionView->append_column("Address", m_instructionColumns->m_address);

		Gtk::TreeView::Column* backwardColumn = Gtk::manage( new Gtk::TreeView::Column("B") );
		for (unsigned i = 0; i < m_nLanes; i++)
			backwardColumn->pack_start(m_instructionColumns->m_backward[i], false);
		m_instructionView->append_column(*backwardColumn);

		m_instructionView->append_column("Instruction", m_instructionColumns->m_instruction);
		Gtk::TreeView::Column* forwardColumn = Gtk::manage( new Gtk::TreeView::Column("F") );
		for (unsigned i = 0; i < m_nLanes; i++)
			forwardColumn->pack_start(m_instructionColumns->m_forward[i], false);
		m_instructionView->append_column(*forwardColumn);

		m_instructionView->append_column("Target", m_instructionColumns->m_target);

		Gtk::FontButton *symbolFont;
		m_builder->get_widget("symbol_font", symbolFont);
		panic_if(!symbolFont,
				"Can't get instruction view");

		Gtk::TreeView *symbolView;
		m_builder->get_widget("symbol_view", symbolView);
		panic_if(!symbolView,
				"Can't get symbol view");
		symbolView->override_font(Pango::FontDescription(symbolFont->get_font_name()));

		symbolView->signal_row_activated().connect(sigc::mem_fun(*this,
				&EmilProGui::onSymbolRowActivated));

		m_instructionView->signal_cursor_changed().connect(sigc::mem_fun(*this,
				&EmilProGui::onInstructionCursorChanged));


		Gtk::FontButton *sourceFont;
		m_builder->get_widget("source_font", sourceFont);
		panic_if(!sourceFont,
				"Can't get source font");

		m_builder->get_widget("source_view", m_sourceView);
		panic_if(!m_sourceView,
				"Can't get source view");
		m_sourceView->override_font(Pango::FontDescription(sourceFont->get_font_name()));

		m_tagTable = Gtk::TextBuffer::TagTable::create();
		Gtk::ColorButton *historyColors[3];
		for (unsigned i = 0; i < 3; i++) {
			m_builder->get_widget(fmt("history_color%d", i).c_str(), historyColors[i]);

			m_sourceTags[i] = Gtk::TextBuffer::Tag::create();


			m_sourceTags[i]->property_paragraph_background_gdk() = historyColors[i]->get_color();
			m_tagTable->add(m_sourceTags[i]);
		}
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
	Glib::RefPtr<Gsv::Buffer> getSourceBuffer(ILineProvider::FileLine &fileLine)
	{
		Glib::RefPtr<Gsv::Buffer> buffer;

		if (!fileLine.m_isValid)
			return buffer;

		if (m_filesToBuffer.find(fileLine.m_file) != m_filesToBuffer.end())
			return m_filesToBuffer[fileLine.m_file];

		size_t sz;
		char *p = (char *)read_file(&sz, "%s", fileLine.m_file.c_str());
		if (!p)
			return buffer;
		std::string data(p, sz);
		free(p);

		Glib::RefPtr<Gsv::LanguageManager> manager = Gsv::LanguageManager::get_default();
		Glib::RefPtr<Gsv::Language> language;

		bool uncertain;
		Glib::ustring content = Gio::content_type_guess(fileLine.m_file, data, uncertain);

		if (uncertain)
			content.clear();

		language = manager->guess_language(fileLine.m_file, content);

		buffer = Gsv::Buffer::create(m_tagTable);
		buffer->set_language(language);
		buffer->set_highlight_syntax(true);

		buffer->begin_not_undoable_action();
		buffer->set_text(data);
		buffer->end_not_undoable_action();

		m_filesToBuffer[fileLine.m_file] = buffer;

		return buffer;
	}

	void onInstructionCursorChanged()
	{
		Gtk::TreeModel::Path path;
		Gtk::TreeViewColumn *column;

		m_instructionView->get_cursor(path, column);

		Gtk::TreeModel::iterator iter = m_instructionListStore->get_iter(path);

		if(!iter)
			return;
		Model &model = Model::instance();

		Gtk::TreeModel::Row row = *iter;
		// FIXME! Should really be a uint64_t...
		Glib::ustring addressStr = row[m_symbolColumns->m_address];
		uint64_t address = strtoull(addressStr.c_str(), NULL, 16);

		ILineProvider::FileLine fileLine = model.getLineByAddress(address);

		Glib::RefPtr<Gsv::Buffer> buffer = getSourceBuffer(fileLine);

		if (m_currentBuffer != buffer) {
			m_sourceView->set_buffer(buffer);
			m_lastSourceLines.clear();
		}
		m_currentBuffer = buffer;

		if (buffer) {
			unsigned int line = fileLine.m_lineNr - 1;

			Gsv::Buffer::iterator it = buffer->get_iter_at_line(line);

			buffer->remove_all_tags(buffer->get_iter_at_line(0), buffer->get_iter_at_line(buffer->get_line_count()));

			m_lastSourceLines.push_back(line);
			if (m_lastSourceLines.size() > 3)
				m_lastSourceLines.pop_front();

			unsigned i = 0;
			for (SourceLineNrList_t::iterator lineIt = m_lastSourceLines.begin();
					lineIt != m_lastSourceLines.end();
					++lineIt, ++i) {
				unsigned int cur = *lineIt;

				Gsv::Buffer::iterator curIt = buffer->get_iter_at_line(cur);
				Gsv::Buffer::iterator itNext = buffer->get_iter_at_line(cur + 1);

				buffer->apply_tag(m_sourceTags[i], curIt, itNext);
			}

			Gtk::ScrolledWindow *sourceScrolledWindow;
			m_builder->get_widget("source_view_scrolled_window", sourceScrolledWindow);

			Glib::RefPtr<Gtk::Adjustment> adj = sourceScrolledWindow->get_vadjustment();

			adj->set_value(adj->get_upper());

			it = buffer->get_iter_at_line(line - 5 < 0 ? 0 : line - 5);
			Glib::RefPtr<Gtk::TextBuffer::Mark> mark = buffer->create_mark(it);

			buffer->place_cursor(it);
			m_sourceView->scroll_to(mark);
			buffer->delete_mark(mark);

			printf("L:%d in %s\n", line + 1, fileLine.m_file.c_str());
		}
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
		unsigned n = 0;
		InstructionList_t insns = model.getInstructions(sym->getAddress(), sym->getAddress() + sym->getSize());

		Gdk::Rectangle rect;
		m_instructionView->get_visible_rect(rect);

		// Number of visible instructions in the view
		unsigned nVisible = rect.get_height() / m_fontHeight + 4;

		m_backwardBranches->calculateLanes(insns, nVisible);
		m_forwardBranches->calculateLanes(insns, nVisible);
		for (InstructionList_t::iterator it = insns.begin();
				it != insns.end();
				++it, ++n) {
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
			JumpTargetDisplay::LaneValue_t lanes[m_nLanes];

			m_backwardBranches->getLanes(n, lanes);
			for (unsigned i = 0; i < m_nLanes; i++)
				row[m_instructionColumns->m_backward[i]] = m_pixbufs[lanes[i]];
			m_forwardBranches->getLanes(n, lanes);
			for (unsigned i = 0; i < m_nLanes; i++)
				row[m_instructionColumns->m_forward[i]] = m_pixbufs[lanes[i]];
		}
	}

	void refresh()
	{
		Model::instance().parseAll();

		m_symbolListStore->clear();

		const Model::SymbolList_t &syms = Model::instance().getSymbols();

		for (Model::SymbolList_t::const_iterator it = syms.begin();
				it != syms.end();
				++it) {
			ISymbol *cur = *it;

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

			row[m_symbolColumns->m_address] = fmt("0x%llx", cur->getAddress()).c_str();
			row[m_symbolColumns->m_size] = fmt("0x%08llx", cur->getSize()).c_str();
			row[m_symbolColumns->m_r] = r;
			row[m_symbolColumns->m_w] = w;
			row[m_symbolColumns->m_x] = x;
			row[m_symbolColumns->m_a] = a;
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
	typedef std::unordered_map<std::string, Glib::RefPtr<Gsv::Buffer>> FileToBufferMap_t;
	typedef std::list<unsigned int> SourceLineNrList_t;

	Gtk::Main *m_app;
	Glib::RefPtr<Gtk::Builder> m_builder;
	Glib::RefPtr<Gtk::ListStore> m_symbolListStore;
	Glib::RefPtr<Gtk::ListStore> m_instructionListStore;
	SymbolModelColumns *m_symbolColumns;
	InstructionModelColumns *m_instructionColumns;
	Gtk::TreeView *m_instructionView;

	JumpTargetDisplay *m_backwardBranches;
	JumpTargetDisplay *m_forwardBranches;

	Glib::RefPtr<Gdk::Pixbuf> m_pixbufs[JumpTargetDisplay::LANE_N_VALUES];
	unsigned m_nLanes;

	unsigned m_fontHeight;

	FileToBufferMap_t m_filesToBuffer;
	Gsv::View *m_sourceView;
	Glib::RefPtr<Gsv::Buffer> m_currentBuffer;


	Glib::RefPtr<Gtk::TextBuffer::Tag> m_sourceTags[3];
	Glib::RefPtr<Gtk::TextBuffer::TagTable> m_tagTable;
	SourceLineNrList_t m_lastSourceLines;
};

int main(int argc, char **argv)
{
	EmilProGui gui;

	gui.init(argc, argv);

	gui.run(argc, argv);

	return 0;
}
