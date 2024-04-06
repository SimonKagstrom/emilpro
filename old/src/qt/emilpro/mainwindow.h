#pragma once

#include <QMainWindow>
#include <qstandarditemmodel.h>

#include <model.hh>
#include <symbolfactory.hh>
#include <addresshistory.hh>
#include <namemangler.hh>
#include <preferences.hh>

#include <unordered_map>

#include "highlighter.h"
#include "jumpdisplay-delegate.h"
#include "editinstructiondialog.h"

#include "QHexEdit/qhexedit.h"
#include "QHexEdit/qhexeditdata.h"

#include <mutex>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow,
	private emilpro::ISymbolListener,
	private emilpro::NameMangler::IListener,
	private emilpro::Preferences::IListener
{
	Q_OBJECT

public:
	explicit MainWindow(QWidget *parent = 0);
	~MainWindow();

	bool init(int argc, char *argv[]);

    // On quit etc
	void updatePreferences();


private slots:
	void on_symbolTableView_activated(const QModelIndex &index);

	void on_instructionTableView_activated(const QModelIndex &index);

	void on_referencesTableView_activated(const QModelIndex &index);

	void on_symbolTableView_entered(const QModelIndex &index);

	void on_addressHistoryListView_activated(const QModelIndex &index);

	void on_sourceTextEdit_cursorPositionChanged();

	void on_insnCurrentChanged(const QModelIndex &current, const QModelIndex &previous);

    void on_instructionTableView_doubleClicked(const QModelIndex &index);

	void on_action_Open_triggered(bool activated);

	void on_action_Refresh_triggered(bool activated);

	void on_action_Quit_triggered(bool activated);

	void on_action_Forward_triggered(bool activated);

	void on_action_Backward_triggered(bool activated);

	void on_action_Mangle_names_triggered(bool activated);

	void on_action_Toggle_data_instructions_triggered(bool activated);

	void on_actionAT_T_syntax_x86_triggered(bool activated);

	void on_action_About_triggered(bool activated);

	void on_editInstructionPushButton_clicked();

	void on_symbolTimerTriggered();

    void on_locationLineEdit_returnPressed();

private:
	typedef std::unordered_map<std::string, std::string> FileToStringMap_t;
	typedef std::unordered_map<int, const emilpro::IInstruction *> RowToInstruction_t;
	typedef std::unordered_map<uint64_t, int> AddressToRow_t;
	typedef std::unordered_map<std::string, int> AddressNameToRow_t;

	void setupSymbolView();

	void setupInstructionView();

	void setupReferencesView();

	void setupAddressHistoryView();

	void setupInstructionLabels();

	void setupInstructionEncoding();

	void setupDataView();

	void setupInfoBox();

	void addHistoryEntry(uint64_t addr);

	void refresh();

	void saveState();

	void restoreState();

	void loadData();

	void updateInstructionView(uint64_t address, const emilpro::ISymbol &sym);

	void updateSymbolView(uint64_t address, const std::string &name = "");

	void updateInfoBox(const emilpro::IInstruction *cur);

	void updateHistoryEntry(const emilpro::AddressHistory::Entry &e);

	void updateInstructionEncoding(const emilpro::IInstruction *insn);

	void updateDataView(uint64_t address, size_t size);

	void handleSymbol(emilpro::ISymbol &sym);

	// From ISymbolListener (called from another thread!)
	void onSymbol(emilpro::ISymbol &sym);

	// From NameMangler::IListener
	void onManglingChanged(bool enabled);

	// From Preferences::IListener
	void onPreferencesChanged(const std::string &key,
			const std::string &oldValue, const std::string &newValue);

	Ui::MainWindow *m_ui{nullptr};
	QStandardItemModel *m_symbolViewModel{nullptr};
	QStandardItemModel *m_instructionViewModel{nullptr};
	QStandardItemModel *m_referencesViewModel{nullptr};
	QStandardItemModel *m_addressHistoryViewModel{nullptr};

	void *m_data{nullptr};
	size_t m_dataSize{0};
	std::string m_currentSourceFile; // Current source file name (cache)
	FileToStringMap_t m_sourceFileMap; // Source file data
	RowToInstruction_t m_rowToInstruction;
	AddressToRow_t m_addressToRow;
	Highlighter *m_highlighter{nullptr};
	emilpro::AddressHistory m_addressHistory;
	bool m_addressHistoryDisabled;

	AddressNameToRow_t m_addressToSymbolRowMap;

	JumpDisplayDelegate m_backwardItemDelegate;
	JumpDisplayDelegate m_forwardItemDelegate;

	EditInstructionDialog *m_editInstructionDialog{nullptr};
	const emilpro::IInstruction *m_currentInstruction{nullptr};

	QHexEdit *m_encodingHexEdit{nullptr};
	QHexEditData *m_encodingData{nullptr};
	QHexEditDataWriter *m_encodingDataWriter{nullptr};

	QHexEdit *m_dataViewHexEdit{nullptr};
	QHexEditData *m_dataViewData{nullptr};
	QHexEditDataWriter *m_dataViewDataWriter{nullptr};

	uint64_t m_dataViewStart{0};
	uint64_t m_dataViewEnd{0};

	emilpro::Model::SymbolList_t m_currentSymbols;
	QTimer *m_timer{nullptr};
	std::mutex m_symbolMutex;
	QString fileName;
	std::string curSymName;
	std::string curSymAddr;
	int64_t curInsnOffset;
};
