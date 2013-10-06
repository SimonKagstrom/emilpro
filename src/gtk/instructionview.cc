#include <instructionview.hh>
#include <symbolview.hh>
#include <iinstruction.hh>
#include <hexview.hh>
#include <infobox.hh>
#include <sourceview.hh>
#include <model.hh>
#include <jumptargetdisplay.hh>
#include <utils.hh>

using namespace emilpro;

class InstructionModelColumns : public Gtk::TreeModelColumnRecord
{
public:
	InstructionModelColumns(unsigned nLanes)
	{
		m_backward = new Gtk::TreeModelColumn<unsigned>[nLanes];
		m_forward = new Gtk::TreeModelColumn<unsigned>[nLanes];

		add(m_address);
		add(m_instruction);
		for (unsigned i = 0; i < nLanes; i++)
			add(m_forward[i]);
		add(m_target);

		for (unsigned i = 0; i < nLanes; i++)
			add(m_backward[i]);
		add(m_rawAddress);
		add(m_bgColor);
		add(m_rawInstruction);
	}

	~InstructionModelColumns()
	{
		delete[] m_backward;
		delete[] m_forward;
	}

	Gtk::TreeModelColumn<Glib::ustring> m_address;
	Gtk::TreeModelColumn<unsigned> *m_backward;
	Gtk::TreeModelColumn<Glib::ustring> m_instruction;
	Gtk::TreeModelColumn<unsigned> *m_forward;
	Gtk::TreeModelColumn<Glib::ustring> m_target;

	// Hidden
	Gtk::TreeModelColumn<uint64_t> m_rawAddress;
	Gtk::TreeModelColumn<Gdk::Color> m_bgColor;
	Gtk::TreeModelColumn<IInstruction *> m_rawInstruction;
};

class AddressHistoryColumns : public Gtk::TreeModelColumnRecord
{
public:
	AddressHistoryColumns()
	{
		add(m_address);
		add(m_symbol);
	}

	Gtk::TreeModelColumn<Glib::ustring> m_address;
	Gtk::TreeModelColumn<Glib::ustring> m_symbol;
};


class JumpLaneCellRenderer : public Gtk::CellRenderer
{
public:
    JumpLaneCellRenderer(InstructionModelColumns *columns, unsigned nLanes, bool isBackward) :
    	Glib::ObjectBase( typeid(JumpLaneCellRenderer) ),
    	Gtk::CellRenderer(),
    	m_width(80),
    	m_nLanes(nLanes),
    	m_laneWidth(m_width / m_nLanes),
    	m_instructionColumns(columns),
    	m_isBackward(isBackward)
    {
    	m_lanes = new JumpTargetDisplay::LaneValue_t[m_nLanes];
    	property_mode() = Gtk::CELL_RENDERER_MODE_INERT;
    }

    virtual ~JumpLaneCellRenderer()
    {
    	delete[] m_lanes;
    }

    void setBackwardDataFunc(Gtk::CellRenderer *renderer, const Gtk::TreeIter iter)
    {
    	Gtk::TreeModel::Row row = *iter;

    	for (unsigned i = 0; i < m_nLanes; i++) {
    		m_lanes[i] = (JumpTargetDisplay::LaneValue_t)(unsigned)row[m_isBackward ?
    				m_instructionColumns->m_backward[i] : m_instructionColumns->m_forward[i]];
    	}
    }

protected:
    virtual void get_preferred_width_vfunc(Gtk::Widget &widget, int &minimum_width, int &natural_width) const
    {
    	minimum_width = m_width;
    	natural_width = m_width;
    }

    virtual void get_preferred_height_for_width_vfunc(Gtk::Widget &widget, int width, int &minimum_height, int &natural_height) const
    {
    	minimum_height = 20;
    	natural_height = 20;
    }

    virtual void get_preferred_height_vfunc(Gtk::Widget &widget, int &minimum_height, int &natural_height) const
    {
    	minimum_height = 20;
    	natural_height = 20;
    }

    virtual void get_preferred_width_for_height_vfunc(Gtk::Widget &widget, int height, int &minimum_width, int &natural_width) const
    {
    	minimum_width = m_width;
    	natural_width = m_width;
    }

    // Overrides
    virtual void get_size_vfunc (Gtk::Widget& widget, const Gdk::Rectangle* cell_area,
    		int* x_offset, int* y_offset, int* width, int* height) const
    {
    }

    virtual void render_vfunc(const ::Cairo::RefPtr< ::Cairo::Context>& cr, Gtk::Widget& widget,
    		const Gdk::Rectangle& background_area, const Gdk::Rectangle& cell_area,
    		Gtk::CellRendererState flags)
    {
    	cr->set_line_width(3.0);

    	cr->set_source_rgb(0, 255, 0);

    	for (unsigned lane = 0; lane < m_nLanes; lane++) {
    		switch (m_lanes[lane])
    		{
    		case JumpTargetDisplay::LANE_LINE:
    			drawLine(cr, widget, cell_area, lane);
    			break;
    		case JumpTargetDisplay::LANE_END_DOWN:
    			drawArrow(cr, widget, cell_area, lane, false, !m_isBackward);
    			break;
    		case JumpTargetDisplay::LANE_END_UP:
    			drawArrow(cr, widget, cell_area, lane, true, !m_isBackward);
    			break;
    		case JumpTargetDisplay::LANE_START_DOWN:
    		case JumpTargetDisplay::LANE_START_UP:
    			drawStart(cr, widget, cell_area, lane, !m_isBackward);
    			break;
    		case JumpTargetDisplay::LANE_START_LONG_DOWN:
    		case JumpTargetDisplay::LANE_START_LONG_UP:
    			drawArrowUpDown(cr, widget, cell_area, lane, !m_isBackward);
    			break;
    		case JumpTargetDisplay::LANE_END_LONG_DOWN:
    			drawLongEnd(cr, widget, cell_area, lane, false, !m_isBackward);
    			break;
    		case JumpTargetDisplay::LANE_END_LONG_UP:
    			drawLongEnd(cr, widget, cell_area, lane, true, !m_isBackward);
    			break;
    		default:
    			break;
    		}
    		cr->stroke();
    	}
    }

private:

	void adjustRectangleByLane(GdkRectangle &r, unsigned lane)
    {
    	r.x += m_laneWidth * lane;
    	r.width = m_laneWidth;
    }

    void drawLine(const ::Cairo::RefPtr< ::Cairo::Context>& cr,
    		Gtk::Widget& widget,
    		const Gdk::Rectangle& cell_area,
    		unsigned lane)
    {
    	GdkRectangle r = *(cell_area.gobj());

    	adjustRectangleByLane(r, lane);

    	cr->move_to(r.x + r.width / 2, r.y);
    	cr->line_to(r.x + r.width / 2, r.y + r.height);
    }

    void drawLongEnd(const ::Cairo::RefPtr< ::Cairo::Context>& cr,
    		Gtk::Widget& widget,
    		const Gdk::Rectangle& cell_area,
    		unsigned lane,
    		bool isRight,
    		bool isUp)
    {
    	GdkRectangle r = *(cell_area.gobj());

    	adjustRectangleByLane(r, lane);

    	unsigned x = r.x + r.width / 2;
    	unsigned startY = r.y;
    	unsigned endY = r.y + r.height / 2;

    	if (!isUp) {
    		startY = r.y + r.height;
    		endY = r.y + r.height / 2;
    	}

    	cr->move_to(x, startY);
    	cr->line_to(x, endY);

    	if (isRight) {
    		unsigned endX = r.x + r.width;

    		cr->line_to(endX, endY);
    		cr->line_to(endX - 5, endY - 5);
    		cr->line_to(endX - 5, endY + 5);
    		cr->line_to(endX, endY);
    	} else {
    		unsigned endX = r.x;

    		cr->line_to(endX, endY);
    		cr->line_to(endX + 5, endY - 5);
    		cr->line_to(endX + 5, endY + 5);
    		cr->line_to(endX, endY);
    	}
    }

    void drawStart(const ::Cairo::RefPtr< ::Cairo::Context>& cr,
    		Gtk::Widget& widget,
    		const Gdk::Rectangle& cell_area,
    		unsigned lane,
    		unsigned isUp)
    {
    	GdkRectangle r = *(cell_area.gobj());

    	adjustRectangleByLane(r, lane);

    	unsigned x = r.x + r.width / 2;
    	unsigned startY = r.y + r.height / 2;
    	unsigned endY = r.y;

    	if (isUp)
    		endY = r.y + r.height;

    	cr->move_to(x, startY);
    	cr->rectangle(x - 5, startY - 5, 10, 10);
    	cr->fill();
    	cr->move_to(x, startY);
    	cr->line_to(x, endY);
    }

    virtual void drawArrow(const ::Cairo::RefPtr< ::Cairo::Context>& cr,
    		Gtk::Widget& widget,
    		const Gdk::Rectangle& cell_area,
    		unsigned lane, bool isRight,
    		bool isUp)
    {
    	GdkRectangle r = *(cell_area.gobj());

    	adjustRectangleByLane(r, lane);

    	unsigned x = r.x + r.width / 2;
    	unsigned startY = r.y;
    	unsigned endY = r.y + r.height / 2;

    	if (!isUp) {
    		startY = r.y + r.height;
    		endY = r.y + r.height / 2;
    	}

    	cr->move_to(x, startY);
    	cr->line_to(x, endY);

    	if (isRight) {
    		unsigned endX = r.x + r.width;

    		cr->line_to(endX, endY);
    		cr->line_to(endX - 5, endY - 5);
    		cr->line_to(endX - 5, endY + 5);
    		cr->line_to(endX, endY);
    	} else {
    		unsigned endX = r.x;

    		cr->line_to(endX, endY);
    		cr->line_to(endX + 5, endY - 5);
    		cr->line_to(endX + 5, endY + 5);
    		cr->line_to(endX, endY);
    	}
    }

    virtual void drawArrowUpDown(const ::Cairo::RefPtr< ::Cairo::Context>& cr,
    		Gtk::Widget& widget,
    		const Gdk::Rectangle& cell_area,
    		unsigned lane,
    		bool isUp)
    {
    	GdkRectangle r = *(cell_area.gobj());

    	adjustRectangleByLane(r, lane);

    	unsigned x = r.x + r.width / 2;
    	unsigned startY = r.y + r.height / 2;
    	unsigned endY = startY + r.height / 3;

    	if (!isUp)
    		endY = startY - r.height / 3;

    	cr->move_to(x, startY);
    	cr->line_to(x, endY);

    	if (isUp) {
    		cr->line_to(x - 5, endY - 5);
    		cr->line_to(x + 5, endY - 5);
    		cr->line_to(x, endY);
    	} else {
    		cr->line_to(x - 5, endY + 5);
    		cr->line_to(x + 5, endY + 5);
    		cr->line_to(x, endY);
    	}
    }


    unsigned m_width;
    unsigned m_nLanes;
    unsigned m_laneWidth;
	InstructionModelColumns *m_instructionColumns;
	JumpTargetDisplay::LaneValue_t *m_lanes;
	bool m_isBackward;
};


InstructionView::InstructionView() :
		m_nLanes(4),
		m_fontHeight(20),
		m_lastInstructionStoreSize(m_nLanes),
		m_instructionColumns(NULL),
		m_treeView(NULL),
		m_addressHistoryColumns(NULL),
		m_addressHistoryTreeView(NULL),
		m_hexView(NULL),
		m_infoBox(NULL),
		m_sourceView(NULL),
		m_historyDisabled(false)
{
	m_backwardBranches = new JumpTargetDisplay(false, m_nLanes);
	m_forwardBranches = new JumpTargetDisplay(true, m_nLanes);
}

InstructionView::~InstructionView()
{
	delete m_backwardBranches;
	delete m_forwardBranches;
	if (m_instructionColumns)
		delete m_instructionColumns;

	if (m_addressHistoryColumns)
		delete m_addressHistoryColumns;
}


void InstructionView::init(Glib::RefPtr<Gtk::Builder> builder, HexView* hv, InfoBox* ib, SourceView *sv, SymbolView *symv, emilpro::AddressHistory *ah)
{
	m_instructionColumns = new InstructionModelColumns(4);

	m_hexView = hv;
	m_infoBox = ib;
	m_sourceView = sv;
	m_symbolView = symv;
	m_addressHistory = ah;

	// FIXME! Get this from properties instead!
	m_backgroundColor = Gdk::Color("white");

	for (unsigned i = 0; i < 3; i++) {
		Gtk::ColorButton *historyColor;

		builder->get_widget(fmt("history_color%d", i).c_str(), historyColor);
		panic_if(!historyColor,
				"Can't get history color");

		m_historyColors[i] = historyColor->get_color();
	}

	m_instructionListStore = Gtk::ListStore::create(*m_instructionColumns);
	panic_if (!m_instructionListStore,
			"Can't get instruction liststore");

	builder->get_widget("instruction_view", m_treeView);
	panic_if(!m_treeView,
			"Can't get view");
	m_addressHistoryColumns = new AddressHistoryColumns();

	Gtk::FontButton *instructionFont;
	builder->get_widget("instruction_font", instructionFont);
	panic_if(!instructionFont,
			"Can't get instruction font");

	m_treeView->override_font(Pango::FontDescription(instructionFont->get_font_name()));
	m_treeView->set_model(m_instructionListStore);
	m_treeView->append_column("Address", m_instructionColumns->m_address);

	Glib::RefPtr<Glib::Object> obj = builder->get_object("address_history_liststore");
	m_addressHistoryListStore = Glib::RefPtr<Gtk::ListStore>::cast_static(obj);
	builder->get_widget("address_history_treeview", m_addressHistoryTreeView);
	panic_if(!m_addressHistoryTreeView,
			"Can't get view");

	m_addressHistoryTreeView->append_column("Address", m_addressHistoryColumns->m_address);
	m_addressHistoryTreeView->append_column("Symbol", m_addressHistoryColumns->m_symbol);
	m_addressHistoryTreeView->set_model(m_addressHistoryListStore);
	m_addressHistoryTreeView->override_font(Pango::FontDescription(instructionFont->get_font_name()));

	m_forwardRenderer = new JumpLaneCellRenderer(m_instructionColumns, m_nLanes, false);
	m_backwardRenderer = new JumpLaneCellRenderer(m_instructionColumns, m_nLanes, true);

	Gtk::TreeView::Column* backwardColumn = Gtk::manage( new Gtk::TreeView::Column("B", *m_backwardRenderer) );
	backwardColumn->set_cell_data_func(*m_backwardRenderer,
			sigc::mem_fun(*m_backwardRenderer, &JumpLaneCellRenderer::setBackwardDataFunc));
	m_treeView->append_column(*backwardColumn);

	m_treeView->append_column("Instruction", m_instructionColumns->m_instruction);
	Gtk::TreeView::Column* forwardColumn = Gtk::manage( new Gtk::TreeView::Column("F", *m_forwardRenderer) );
	forwardColumn->set_cell_data_func(*m_forwardRenderer,
			sigc::mem_fun(*m_forwardRenderer, &JumpLaneCellRenderer::setBackwardDataFunc));
	m_treeView->append_column(*forwardColumn);

	m_treeView->append_column("Target", m_instructionColumns->m_target);

	m_treeView->signal_cursor_changed().connect(sigc::mem_fun(*this,
			&InstructionView::onCursorChanged));
	m_treeView->signal_row_activated().connect(sigc::mem_fun(*this,
			&InstructionView::onRowActivated));

	Gtk::TreeViewColumn *cp;
	Gtk::CellRenderer *cr;

	cp = m_treeView->get_column(2);

	cr = cp->get_first_cell();
	cp->add_attribute(cr->property_cell_background_gdk(), m_instructionColumns->m_bgColor);

	m_treeView->set_search_column(1);
}

void InstructionView::update(uint64_t address, const emilpro::ISymbol& sym)
{
	Model &model = Model::instance();

	m_instructionListStore->clear();
	m_lastInstructionIters.clear();

	// Disassemble and display
	unsigned n = 0;
	InstructionList_t insns = model.getInstructions(sym.getAddress(), sym.getAddress() + sym.getSize());

	Gdk::Rectangle rect;
	m_treeView->get_visible_rect(rect);

	// Number of visible instructions in the view
	unsigned nVisible = rect.get_height() / m_fontHeight + 4;

	Gtk::ListStore::iterator newCursor;

	m_backwardBranches->calculateLanes(insns, nVisible);
	m_forwardBranches->calculateLanes(insns, nVisible);
	for (InstructionList_t::iterator it = insns.begin();
			it != insns.end();
			++it, ++n) {
		IInstruction *cur = *it;

		Gtk::ListStore::iterator rowIt = m_instructionListStore->append();
		Gtk::TreeRow row = *rowIt;

		row[m_instructionColumns->m_address] = fmt("0x%0llx", (long long)cur->getAddress()).c_str();
		row[m_instructionColumns->m_instruction] = cur->getString();

		if (cur->getBranchTargetAddress() != IInstruction::INVALID_ADDRESS) {
			uint64_t target = cur->getBranchTargetAddress();
			Model::SymbolList_t targetSyms = model.getSymbolExact(target);

			if (targetSyms.empty() || (target >= sym.getAddress() && target < sym.getAddress() + sym.getSize())) {
				row[m_instructionColumns->m_target] = fmt("0x%0llx", (long long)cur->getBranchTargetAddress()).c_str();
			} else {
				const ISymbol *targetSym = targetSyms.front();

				row[m_instructionColumns->m_target] = targetSym->getName();
			}
		}
		JumpTargetDisplay::LaneValue_t lanes[m_nLanes];

		m_backwardBranches->getLanes(n, lanes);
		for (unsigned i = 0; i < m_nLanes; i++)
			row[m_instructionColumns->m_backward[i]] = lanes[i];
		m_forwardBranches->getLanes(n, lanes);
		for (unsigned i = 0; i < m_nLanes; i++)
			row[m_instructionColumns->m_forward[i]] = lanes[i];

		row[m_instructionColumns->m_rawAddress] = cur->getAddress();
		row[m_instructionColumns->m_rawInstruction] = cur;

		if (cur->getAddress() == address)
			newCursor = rowIt;
	}

	if (!m_historyDisabled)
		addAddressHistoryEntry(address);
	m_treeView->set_cursor(m_instructionListStore->get_path(newCursor));
}

void InstructionView::onCursorChanged()
{
	Gtk::TreeModel::Path path;
	Gtk::TreeViewColumn *column;

	m_treeView->get_cursor(path, column);

	Gtk::TreeModel::iterator iter = m_instructionListStore->get_iter(path);

	if(!iter)
		return;

	if (m_instructionListStore->children().size() != m_lastInstructionStoreSize) {
		m_lastInstructionIters.clear();
		m_lastInstructionStoreSize = m_instructionListStore->children().size();
	}

	m_lastInstructionIters.push_back(iter);

	if (m_lastInstructionIters.size() > 3) {
		Gtk::TreeModel::iterator last = m_lastInstructionIters.front();
		if (m_instructionListStore->iter_is_valid(last)) {
			Gtk::TreeModel::Row lastRow = *last;

			lastRow[m_instructionColumns->m_bgColor] = m_backgroundColor;
		}
		m_lastInstructionIters.pop_front();
	}

	unsigned i = 0;
	for (InstructionIterList_t::iterator it = m_lastInstructionIters.begin();
			it != m_lastInstructionIters.end();
			++it, ++i) {
		Gtk::TreeModel::iterator cur = *it;
		if (m_instructionListStore->iter_is_valid(cur)) {
			Gtk::TreeModel::Row curRow = *cur;

			curRow[m_instructionColumns->m_bgColor] = m_historyColors[i];
		}
	}

	Gtk::TreeModel::Row row = *iter;
	uint64_t address = row[m_instructionColumns->m_rawAddress];
	IInstruction *cur = row[m_instructionColumns->m_rawInstruction];

	if (cur) {
		m_hexView->markRange(cur->getAddress(), (size_t)cur->getSize());
		m_infoBox->onInstructionSelected(*cur);
		m_hexView->updateInstructionEncoding(cur->getAddress(), (size_t)cur->getSize());
	}

	m_sourceView->update(address);
}

void InstructionView::disableHistory()
{
	m_historyDisabled = true;
}

void InstructionView::enableHistory()
{
	m_historyDisabled = false;
}

void InstructionView::onRowActivated(const Gtk::TreeModel::Path& path, Gtk::TreeViewColumn* column)
{
	Gtk::TreeModel::iterator iter = m_instructionListStore->get_iter(path);
	Gtk::TreeModel::Row row = *iter;
	IInstruction *cur = row[m_instructionColumns->m_rawInstruction];

	if (!cur)
		return;

	if (cur->getType() != IInstruction::IT_CFLOW && cur->getType() != IInstruction::IT_CALL)
		return;

	uint64_t target = cur->getBranchTargetAddress();

	if (target == IInstruction::INVALID_ADDRESS)
		return;

	Model &model = Model::instance();

	// Lookup symbol for this instruction
	const Model::SymbolList_t syms = model.getNearestSymbol(cur->getAddress());
	if (syms.size() == 0)
		return;

	for (Model::SymbolList_t::const_iterator sIt = syms.begin();
			sIt != syms.end();
			++sIt) {
		const ISymbol *sym = *sIt;

		if (sym->getType() != ISymbol::SYM_TEXT)
			continue;

		if (!m_historyDisabled)
			addAddressHistoryEntry(cur->getAddress());
		// FIXME!
		if (target >= sym->getAddress() && target < sym->getAddress() + sym->getSize())
			printf("Jump within function\n");
		else
			m_symbolView->update(target);
	}
}

void InstructionView::addAddressHistoryEntry(uint64_t address)
{
	Model &model = Model::instance();
	bool res = m_addressHistory->maybeAddEntry(address);

	if (!res)
		return;

	const Model::SymbolList_t syms = model.getNearestSymbol(address);

	const ISymbol *p = NULL;
	for (Model::SymbolList_t::const_iterator sIt = syms.begin();
			sIt != syms.end();
			++sIt) {
		const ISymbol *sym = *sIt;

		if (sym->getType() != ISymbol::SYM_TEXT)
			continue;
		p = sym;
	}

	std::string symName = "";

	if (p)
		symName = p->getName();

	Gtk::ListStore::iterator rowIt = m_addressHistoryListStore->append();
	Gtk::TreeRow row = *rowIt;

	row[m_addressHistoryColumns->m_address] = fmt("0x%0llx", (long long)address).c_str();
	row[m_addressHistoryColumns->m_symbol] = symName;
}
