#pragma once

#include <isymbol.hh>

#include <gtkmm.h>
#include <unordered_map>

class InstructionView;
class HexView;
class SymbolModelColumns;
class ReferenceModelColumns;

class SymbolView
{
public:
	SymbolView();

	~SymbolView();

	void init(Glib::RefPtr<Gtk::Builder> builder, InstructionView *iv, HexView *hv);

	void update(uint64_t address);

	void refreshSymbols();

private:
	void onCursorChanged();

	void onRowActivated(const Gtk::TreeModel::Path& path, Gtk::TreeViewColumn* column);

	void onReferenceRowActivated(const Gtk::TreeModel::Path& path, Gtk::TreeViewColumn* column);

	void updateSourceView(uint64_t address, const emilpro::ISymbol *sym);

	void updateDataView(uint64_t address, const emilpro::ISymbol *sym);


	void onEntryActivated();

	typedef std::unordered_map<uint64_t, Gtk::ListStore::iterator> SymbolRowIterByAddressMap_t;

	Glib::RefPtr<Gtk::ListStore> m_symbolListStore;
	SymbolRowIterByAddressMap_t m_symbolRowIterByAddress;
	Glib::RefPtr<Gtk::ListStore> m_referencesListStore;
	SymbolModelColumns *m_symbolColumns;
	ReferenceModelColumns *m_referenceColumns;
	Gtk::Notebook *m_instructionsDataNotebook;

	Gtk::TreeView *m_symbolView;
	Gtk::TreeView *m_referencesView;
	Gtk::Entry *m_lookupEntry;
	InstructionView *m_instructionView;
	HexView *m_hexView;
};
