#pragma once

#include <isymbol.hh>
#include <namemangler.hh>
#include <symbolfactory.hh>
#include <addresshistory.hh>
#include <model.hh>

#include <gtkmm.h>
#include <sigc++/sigc++.h>
#include <unordered_map>
#include <string>
#include <mutex>

class InstructionView;
class HexView;
class SymbolModelColumns;
class ReferenceModelColumns;

class SymbolView : public emilpro::NameMangler::IListener, public emilpro::ISymbolListener
{
public:
	SymbolView();

	~SymbolView();

	void init(Glib::RefPtr<Gtk::Builder> builder, InstructionView *iv, HexView *hv, emilpro::AddressHistory *ah);

	void update(uint64_t address, const std::string &name = "");

	void refreshSymbols();

private:
	bool onSearchEqual(const Glib::RefPtr<Gtk::TreeModel>& model, int column, const Glib::ustring& key, const Gtk::TreeModel::iterator& iter);

	// From ISymbolListener
	void onSymbol(emilpro::ISymbol &sym);

	void onSymbolSignal();

	void onSymbolImpl(const emilpro::ISymbol &sym);

	void onCursorChanged();

	void onRowActivated(const Gtk::TreeModel::Path& path, Gtk::TreeViewColumn* column);

	void onReferenceRowActivated(const Gtk::TreeModel::Path& path, Gtk::TreeViewColumn* column);

	void updateSourceView(uint64_t address, const emilpro::ISymbol *sym);

	void updateDataView(uint64_t address, const emilpro::ISymbol *sym);


	void onEntryActivated();

	// From NameMangler::IListener
	void onManglingChanged(bool enabled);

	void onManglingChangedSignal();


	typedef std::unordered_map<uint64_t, Gtk::ListStore::iterator> SymbolRowIterByAddressMap_t;
	typedef std::unordered_map<std::string, Gtk::ListStore::iterator> SymbolRowIterByNameMap_t;

	Glib::RefPtr<Gtk::ListStore> m_addressHistoryListStore;
	Glib::RefPtr<Gtk::ListStore> m_symbolListStore;
	SymbolRowIterByAddressMap_t m_symbolRowIterByAddress;
	SymbolRowIterByNameMap_t m_symbolRowIterByName;
	Glib::RefPtr<Gtk::ListStore> m_referencesListStore;
	SymbolModelColumns *m_symbolColumns;
	ReferenceModelColumns *m_referenceColumns;
	Gtk::Notebook *m_instructionsDataNotebook;

	Gtk::TreeView *m_symbolView;
	Gtk::TreeView *m_referencesView;
	Gtk::Entry *m_lookupEntry;
	InstructionView *m_instructionView;
	HexView *m_hexView;
	emilpro::AddressHistory *m_addressHistory;
	sigc::connection m_cursorChangedSignal;


	std::mutex m_mutex;
	emilpro::Model::SymbolList_t m_pendingSymbols;
	Glib::Dispatcher m_symbolSignal;
	Glib::Dispatcher m_manglingSignal;
	std::thread::id m_mainThreadId;
};
