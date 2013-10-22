#pragma once

#include <isymbol.hh>
#include <jumptargetdisplay.hh>
#include <addresshistory.hh>

#include <gtkmm.h>

class HexView;
class InfoBox;
class SourceView;
class SymbolView;
class InstructionModelColumns;
class AddressHistoryColumns;
class JumpLaneCellRenderer;

class InstructionView
{
public:
	InstructionView();

	~InstructionView();

	void init(Glib::RefPtr<Gtk::Builder> builder, HexView *hv, InfoBox *ib, SourceView *sv, SymbolView *symv, emilpro::AddressHistory *ah);

	void update(uint64_t address, const emilpro::ISymbol &sym);

	void disableHistory();

	void enableHistory();

private:
	typedef std::list<Gtk::TreeModel::iterator> InstructionIterList_t;
	bool onSearchEqual(const Glib::RefPtr<Gtk::TreeModel>& model, int column, const Glib::ustring& key, const Gtk::TreeModel::iterator& iter);

	void onCursorChanged();

	void onRowActivated(const Gtk::TreeModel::Path& path, Gtk::TreeViewColumn* column);

	void addAddressHistoryEntry(uint64_t address);

	unsigned m_nLanes;
	unsigned m_fontHeight;

	InstructionIterList_t m_lastInstructionIters;
	unsigned m_lastInstructionStoreSize;

	Glib::RefPtr<Gtk::ListStore> m_instructionListStore;
	InstructionModelColumns *m_instructionColumns;
	Gtk::TreeView *m_treeView;

	Glib::RefPtr<Gtk::ListStore> m_addressHistoryListStore;
	AddressHistoryColumns *m_addressHistoryColumns;
	Gtk::TreeView *m_addressHistoryTreeView;

	HexView *m_hexView;
	InfoBox *m_infoBox;
	SourceView *m_sourceView;
	SymbolView *m_symbolView;

	Gdk::Color m_historyColors[3];
	Gdk::Color m_backgroundColor;

	JumpLaneCellRenderer *m_backwardRenderer;
	JumpLaneCellRenderer *m_forwardRenderer;
	emilpro::JumpTargetDisplay *m_backwardBranches;
	emilpro::JumpTargetDisplay *m_forwardBranches;
	emilpro::AddressHistory *m_addressHistory;

	bool m_historyDisabled;
};
