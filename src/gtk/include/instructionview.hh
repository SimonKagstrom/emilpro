#pragma once

#include <isymbol.hh>
#include <jumptargetdisplay.hh>

#include <gtkmm.h>

class HexView;
class InfoBox;
class SourceView;
class SymbolView;
class InstructionModelColumns;
class JumpLaneCellRenderer;

class InstructionView
{
public:
	InstructionView();

	~InstructionView();

	void init(Glib::RefPtr<Gtk::Builder> builder, HexView *hv, InfoBox *ib, SourceView *sv, SymbolView *symv);

	void update(uint64_t address, const emilpro::ISymbol &sym);

private:
	typedef std::list<Gtk::TreeModel::iterator> InstructionIterList_t;

	void onCursorChanged();

	void onRowActivated(const Gtk::TreeModel::Path& path, Gtk::TreeViewColumn* column);

	unsigned m_nLanes;
	unsigned m_fontHeight;

	InstructionIterList_t m_lastInstructionIters;
	unsigned m_lastInstructionStoreSize;

	Glib::RefPtr<Gtk::ListStore> m_instructionListStore;
	InstructionModelColumns *m_instructionColumns;
	Gtk::TreeView *m_treeView;

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
};
