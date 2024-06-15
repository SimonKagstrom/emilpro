#pragma once

#include "emilpro/address_history.hh"
#include "emilpro/database.hh"
#include "emilpro/i_binary_parser.hh"
#include "emilpro/i_instruction.hh"
#include "highlighter.hh"
#include "instruction_delegate.hh"
#include "jump_lane_delegate.hh"

#include <QMainWindow>
#include <qstandarditemmodel.h>

namespace Ui
{
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = 0);
    ~MainWindow();

    bool Init(int argc, char* argv[]);

    // On quit etc
    void UpdatePreferences();

private slots:
    void on_symbolTableView_activated(const QModelIndex& index);
    void on_symbolTableView_entered(const QModelIndex& index);

    void on_instructionTableView_activated(const QModelIndex& index);

    void on_refersToTableView_activated(const QModelIndex& index);

    void on_addressHistoryListView_activated(const QModelIndex& index);

    void on_sourceTextEdit_cursorPositionChanged();

    void on_insnCurrentChanged(const QModelIndex& current, const QModelIndex& previous);

    void on_instructionTableView_doubleClicked(const QModelIndex& index);

    void on_action_Open_triggered(bool activated);

    void on_action_Refresh_triggered(bool activated);

    void on_action_Quit_triggered(bool activated);

    void on_action_Forward_triggered(bool activated);

    void on_action_Backward_triggered(bool activated);

    void on_action_FocusLocationBar_triggered(bool activated);

    void on_action_Mangle_names_triggered(bool activated);

    void on_action_Toggle_data_instructions_triggered(bool activated);

    void on_actionAT_T_syntax_x86_triggered(bool activated);

    void on_action_About_triggered(bool activated);

    void on_symbolTimerTriggered();

    void on_locationLineEdit_textChanged(const QString& text);
    void on_locationLineEdit_returnPressed();

private:
    void SetupSectionView();

    void SetupSymbolView();

    void SetupInstructionView();

    void SetupReferencesView();

    void SetupAddressHistoryView();

    void SetupInstructionLabels();

    void SetupInstructionEncoding();

    void SetupDataView();

    void SetupInfoBox();

    void addHistoryEntry(uint64_t addr);

    void refresh();

    void LoadFile(const std::string& filename);

    void saveState();

    void restoreState();

    void UpdateInstructionView(const emilpro::ISymbol& symbol, uint64_t offset);

    void UpdateRefersToView(const emilpro::ISymbol& symbol);
    void UpdateRefersToView(const emilpro::IInstruction& insn);

    void UpdateReferredByView(const emilpro::ISymbol& symbol);
    void UpdateReferredByView(const emilpro::IInstruction& insn);

    void UpdateSymbolView(const emilpro::ISymbol& symbol);

    void UpdateHistoryView();

    const QString& LookupSourceFile(std::string_view);

    // From https://forum.qt.io/topic/76265/set-background-of-specific-row-in-qtableview/2
    void SetRowColor(QAbstractItemModel* model,
                     int row,
                     const QBrush& color,
                     const QModelIndex& parent = QModelIndex());

    bool eventFilter(QObject* watched, QEvent* event) final;

    Ui::MainWindow* m_ui {nullptr};
    QStandardItemModel* m_section_view_model {nullptr};
    QStandardItemModel* m_symbol_view_model {nullptr};
    QStandardItemModel* m_instruction_view_model {nullptr};
    QStandardItemModel* m_refers_to_view_model {nullptr};
    QStandardItemModel* m_referred_by_view_model {nullptr};
    QStandardItemModel* m_address_history_view_model {nullptr};

    const emilpro::ISymbol* m_current_symbol {nullptr};

    JumpLaneDelegate m_forward_item_delegate;
    JumpLaneDelegate m_backward_item_delegate;
    InstructionDelegate m_instruction_item_delegate;

    Highlighter* m_highlighter {nullptr};
    std::unordered_map<std::string, QString> m_source_file_map;
    QString m_current_source_file;


    emilpro::Database m_database;
    emilpro::AddressHistory m_address_history;

    std::span<const std::reference_wrapper<emilpro::IInstruction>> m_visible_instructions;
    std::span<const std::reference_wrapper<emilpro::ISymbol>> m_visible_symbols;
};
