#include <symbolview.hh>

#include <instructionview.hh>
#include <hexview.hh>
#include <model.hh>
#include <utils.hh>
#include <ui-helpers.hh>

using namespace emilpro;

class SymbolModelColumns : public Gtk::TreeModelColumnRecord
{
public:
	SymbolModelColumns()
	{
		add(m_address);
		add(m_size);
		add(m_l);
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
		return 8;
	}

	Gtk::TreeModelColumn<Glib::ustring> m_address;
	Gtk::TreeModelColumn<Glib::ustring> m_size;
	Gtk::TreeModelColumn<Glib::ustring> m_l;
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


SymbolView::SymbolView() :
		m_instructionView(NULL),
		m_hexView(NULL)
{
	m_symbolSignal.connect(sigc::mem_fun(this, &SymbolView::onSymbolSignal) );
	m_manglingSignal.connect(sigc::mem_fun(this, &SymbolView::onManglingChangedSignal) );
}

SymbolView::~SymbolView()
{
	delete m_symbolColumns;
	delete m_referenceColumns;
}

void SymbolView::init(Glib::RefPtr<Gtk::Builder> builder, InstructionView *iv, HexView *hv, emilpro::AddressHistory *ah)
{
	m_mainThreadId = std::this_thread::get_id();

	m_instructionView = iv;
	m_hexView = hv;
	m_addressHistory = ah;

	m_symbolColumns = new SymbolModelColumns();
	m_referenceColumns = new ReferenceModelColumns();

	Gtk::FontButton *symbolFont;
	builder->get_widget("symbol_font", symbolFont);
	panic_if(!symbolFont,
			"Can't get instruction view");

	NameMangler::instance().registerListener(this);

	builder->get_widget("symbol_view", m_symbolView);
	panic_if(!m_symbolView,
			"Can't get symbol view");
	m_symbolView->override_font(Pango::FontDescription(symbolFont->get_font_name()));

	m_symbolListStore = Gtk::ListStore::create(*m_symbolColumns);
	m_symbolView->append_column("Address", m_symbolColumns->m_address);
	m_symbolView->append_column("Size", m_symbolColumns->m_size);
	m_symbolView->append_column("Lnk", m_symbolColumns->m_l);
	m_symbolView->append_column("R", m_symbolColumns->m_r);
	m_symbolView->append_column("W", m_symbolColumns->m_w);
	m_symbolView->append_column("X", m_symbolColumns->m_x);
	m_symbolView->append_column("A", m_symbolColumns->m_a);
	m_symbolView->append_column("Symbol name", m_symbolColumns->m_name);

	m_symbolView->set_model(m_symbolListStore);

	m_symbolView->signal_row_activated().connect(sigc::mem_fun(*this,
			&SymbolView::onRowActivated));
	m_cursorChangedSignal = m_symbolView->signal_cursor_changed().connect(sigc::mem_fun(*this,
			&SymbolView::onCursorChanged));

	for (unsigned i = 0; i < m_symbolColumns->getNumberOfVisibleColumns(); i++) {
		Gtk::TreeViewColumn *cp;
		Gtk::CellRenderer *cr;

		cp = m_symbolView->get_column(i);

		cr = cp->get_first_cell();

		cp->add_attribute(cr->property_cell_background_gdk(), m_symbolColumns->m_bgColor);
	}

	Glib::RefPtr<Glib::Object> obj = builder->get_object("address_history_liststore");
	m_addressHistoryListStore = Glib::RefPtr<Gtk::ListStore>::cast_static(obj);

	builder->get_widget("references_view", m_referencesView);
	panic_if(!m_referencesView,
			"Can't get reference view");

	m_referencesListStore = Gtk::ListStore::create(*m_referenceColumns);
	m_referencesView->append_column("Symbol references", m_referenceColumns->m_symbol);

	m_referencesView->set_model(m_referencesListStore);

	Gtk::FontButton *referencesFont;
	builder->get_widget("references_font", referencesFont);
	panic_if(!referencesFont,
			"Can't get references font");

	m_referencesView->override_font(Pango::FontDescription(referencesFont->get_font_name()));

	m_referencesView->signal_row_activated().connect(sigc::mem_fun(*this,
			&SymbolView::onReferenceRowActivated));

	builder->get_widget("instructions_data_notebook", m_instructionsDataNotebook);
	panic_if(!m_instructionsDataNotebook, "Can't get notebook");

	builder->get_widget("symbol_lookup_entry", m_lookupEntry);
	panic_if(!m_lookupEntry, "Can't get entry");

	m_lookupEntry->signal_activate().connect(sigc::mem_fun(*this,
			&SymbolView::onEntryActivated));

	m_symbolView->set_search_column(6);
	m_symbolView->set_search_equal_func(sigc::mem_fun(*this, &SymbolView::onSearchEqual));
}

// False means match here
bool SymbolView::onSearchEqual(const Glib::RefPtr<Gtk::TreeModel>& model, int column, const Glib::ustring& key, const Gtk::TreeModel::iterator& iter)
{
	Gtk::TreeModel::Row row = *iter;
	uint64_t address = row[m_symbolColumns->m_rawAddress];

	Glib::ustring name = row[m_symbolColumns->m_name];

	if (name.find(key) != std::string::npos)
		return false;

	if (!string_is_integer(key, 16))
		return true;

	const Model::SymbolList_t syms = Model::instance().getNearestSymbol(address);
	uint64_t keyAddr = string_to_integer(key, 16);

	for (Model::SymbolList_t::const_iterator it = syms.begin();
			it != syms.end();
			++it) {
		ISymbol *cur = *it;

		if (cur->getType() != ISymbol::SYM_TEXT && cur->getType() != ISymbol::SYM_DATA)
			continue;

		if (keyAddr >= cur->getAddress() && keyAddr < cur->getAddress() + cur->getSize())
			return false;
	}

	return true;
}

void SymbolView::onCursorChanged()
{
	Gtk::TreeModel::Path path;
	Gtk::TreeViewColumn *column;

	m_symbolView->get_cursor(path, column);

	Gtk::TreeModel::iterator iter = m_symbolListStore->get_iter(path);

	m_referencesListStore->clear();

	if(!iter)
		return;
	Model &model = Model::instance();
	NameMangler &mv = NameMangler::instance();

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
				std::string name = mv.mangle(sym->getName());

				row[m_referenceColumns->m_symbol] = fmt("%s+0x%llx", name.c_str(), (long long)(cur - sym->getAddress()));
				row[m_referenceColumns->m_rawAddress] = cur;
			}
		}
	}
}

void SymbolView::onRowActivated(const Gtk::TreeModel::Path& path,
		Gtk::TreeViewColumn* column)
{
	uint64_t address;
	Glib::ustring name;

	Gtk::TreeModel::iterator iter = m_symbolListStore->get_iter(path);

	if(!iter)
		return;

	Gtk::TreeModel::Row row = *iter;
	address = row[m_symbolColumns->m_rawAddress];
	name = row[m_symbolColumns->m_name];

	update(address, name);
}

void SymbolView::onReferenceRowActivated(const Gtk::TreeModel::Path& path,
		Gtk::TreeViewColumn* column)
{
	uint64_t address;

	Gtk::TreeModel::iterator iter = m_referencesListStore->get_iter(path);

	if(!iter)
		return;

	Gtk::TreeModel::Row row = *iter;
	address = row[m_referenceColumns->m_rawAddress];

	if (address == IInstruction::INVALID_ADDRESS)
		return;

	update(address);
}

void SymbolView::updateSourceView(uint64_t address, const emilpro::ISymbol* sym)
{
	m_instructionsDataNotebook->set_current_page(0);

	m_instructionView->update(address, *sym);
}

void SymbolView::refreshSymbols()
{
	m_cursorChangedSignal.disconnect();
	m_referencesListStore->clear();
	m_symbolListStore->clear();
	m_symbolRowIterByAddress.clear();
	m_symbolRowIterByName.clear();

	// The onSymbol callback will handle this
	Model::instance().parseAll();
	m_cursorChangedSignal = m_symbolView->signal_cursor_changed().connect(sigc::mem_fun(*this,
			&SymbolView::onCursorChanged));
}

void SymbolView::update(uint64_t address, const std::string &name)
{
	Gtk::TreeModel::Path path;

	const ISymbol *best = UiHelpers::getBestSymbol(address, name);

	if (!best)
		return;

	if (best->isExecutable())
		m_instructionView->update(address, *best);
	else
		updateDataView(address, best);

	m_symbolView->set_cursor(path);
}

void SymbolView::updateDataView(uint64_t address, const emilpro::ISymbol* sym)
{
	m_instructionsDataNotebook->set_current_page(1);

	m_hexView->markRange(sym->getAddress(), (size_t)sym->getSize());
}

void SymbolView::onEntryActivated()
{
	std::string text = m_lookupEntry->get_text();

	m_addressHistory->clear();
	m_addressHistoryListStore->clear();
	Model::AddressList_t lst = Model::instance().lookupAddressesByText(text);

	for (Model::AddressList_t::iterator it = lst.begin();
			it != lst.end();
			++it) {
		update(*it);
	}
}

void SymbolView::onSymbolSignal()
{
	m_mutex.lock();
	for (Model::SymbolList_t::iterator it = m_pendingSymbols.begin();
			it != m_pendingSymbols.end();
			++it) {
		ISymbol *cur = *it;

		onSymbolImpl(*cur);
	}
	m_pendingSymbols.clear();
	m_mutex.unlock();
}

void SymbolView::onSymbolImpl(const emilpro::ISymbol &sym)
{
	NameMangler &mv = NameMangler::instance();

	// Skip the file symbol
	if (sym.getType() == ISymbol::SYM_FILE)
		return;

	Gtk::ListStore::iterator rowIt = m_symbolListStore->append();
	Gtk::TreeRow row = *rowIt;

	m_symbolRowIterByAddress[sym.getAddress()] = rowIt;
	m_symbolRowIterByName[sym.getName()] = rowIt;

	std::string name = mv.mangle(sym.getName());
	const char *r = "R";
	const char *w = sym.isWriteable() ? "W" : " ";
	const char *x = sym.isExecutable() ? "X" : " ";
	const char *a = sym.isAllocated() ? "A" : " ";
	const char *link_str = "";

	auto linkage = sym.getLinkage();
	if (linkage == ISymbol::LINK_DYNAMIC)
		link_str = "D";
	else if (linkage == ISymbol::LINK_UNDEFINED)
		link_str = "U";

	row[m_symbolColumns->m_address] = fmt("0x%llx", (long long)sym.getAddress()).c_str();
	row[m_symbolColumns->m_size] = fmt("0x%08llx", (long long)sym.getSize()).c_str();
	row[m_symbolColumns->m_l] = link_str;
	row[m_symbolColumns->m_r] = r;
	row[m_symbolColumns->m_w] = w;
	row[m_symbolColumns->m_x] = x;
	row[m_symbolColumns->m_a] = a;
	row[m_symbolColumns->m_name] = fmt("%s%s",
			sym.getType() == ISymbol::SYM_SECTION ? "Section " : "", name.c_str());

	row[m_symbolColumns->m_rawAddress] = sym.getAddress();
}

void SymbolView::onSymbol(ISymbol& sym)
{
	std::thread::id id = std::this_thread::get_id();

	if (id == m_mainThreadId) {
		onSymbolImpl(sym);
		return;
	}

	// Pass these via IPC (these are much less common)
	m_mutex.lock();
	m_pendingSymbols.push_back(&sym);
	m_mutex.unlock();

	m_symbolSignal();
}

void SymbolView::onManglingChangedSignal()
{
	refreshSymbols();
}

void SymbolView::onManglingChanged(bool enabled)
{
	m_manglingSignal();
}

