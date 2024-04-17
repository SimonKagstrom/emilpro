#pragma once

#include "emilpro/database.hh"
#include "emilpro/i_binary_parser.hh"

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

    bool init(int argc, char* argv[]);

    // On quit etc
    void updatePreferences();

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

    void UpdateInstructionView(uint64_t offset);

    void updateSymbolView(uint64_t address, const std::string& name = "");

    void updateDataView(uint64_t address, size_t size);

    Ui::MainWindow* m_ui {nullptr};
    QStandardItemModel* m_symbol_view_model {nullptr};
    QStandardItemModel* m_instruction_view_model {nullptr};
    QStandardItemModel* m_references_view_model {nullptr};
    QStandardItemModel* m_addressHistory_view_model {nullptr};

    emilpro::Database m_database;

    std::span<const std::reference_wrapper<emilpro::IInstruction>> m_visible_instructions;
    std::span<const std::reference_wrapper<emilpro::ISymbol>> m_visible_symbols;
};
