#pragma once

#include "emilpro/database.hh"
#include "emilpro/i_binary_parser.hh"
#include "emilpro/i_instruction.hh"
#include "highlighter.hh"
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

    void on_instructionTableView_activated(const QModelIndex& index);

    void on_referencesTableView_activated(const QModelIndex& index);

    void on_symbolTableView_entered(const QModelIndex& index);

    void on_addressHistoryListView_activated(const QModelIndex& index);

    void on_sourceTextEdit_cursorPositionChanged();

    void on_insnCurrentChanged(const QModelIndex& current, const QModelIndex& previous);

    void on_instructionTableView_doubleClicked(const QModelIndex& index);

    void on_action_Open_triggered(bool activated);

    void on_action_Refresh_triggered(bool activated);

    void on_action_Quit_triggered(bool activated);

    void on_action_Forward_triggered(bool activated);

    void on_action_Backward_triggered(bool activated);

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

    void saveState();

    void restoreState();

    void UpdateInstructionView(uint64_t offset);

    void UpdateSymbolView(uint64_t address, const std::string& name = "");

    void UpdateDataView(uint64_t address, size_t size);

    const QString& LookupSourceFile(std::string_view);

    Ui::MainWindow* m_ui {nullptr};
    QStandardItemModel* m_section_view_model {nullptr};
    QStandardItemModel* m_symbol_view_model {nullptr};
    QStandardItemModel* m_instruction_view_model {nullptr};
    QStandardItemModel* m_references_view_model {nullptr};
    QStandardItemModel* m_addressHistory_view_model {nullptr};

    JumpLaneDelegate m_forward_item_delegate;
    JumpLaneDelegate m_backward_item_delegate;

    Highlighter* m_highlighter {nullptr};
    std::unordered_map<std::string, QString> m_source_file_map;
    QString m_current_source_file;


    emilpro::Database m_database;

    std::span<const std::reference_wrapper<emilpro::IInstruction>> m_visible_instructions;
    std::span<const std::reference_wrapper<emilpro::ISymbol>> m_visible_symbols;
};
