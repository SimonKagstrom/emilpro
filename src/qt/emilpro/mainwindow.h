#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <qstandarditemmodel.h>

#include <model.hh>
#include <symbolfactory.hh>
#include <addresshistory.hh>

#include <unordered_map>

#include "highlighter.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow, public emilpro::ISymbolListener
{
    Q_OBJECT
    
public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    
    bool init(int argc, char *argv[]);


private slots:
    void on_symbolTableView_activated(const QModelIndex &index);

    void on_instructionTableView_activated(const QModelIndex &index);

    void on_instructionTableView_entered(const QModelIndex &index);

    void on_referencesListView_activated(const QModelIndex &index);

    void on_symbolTableView_entered(const QModelIndex &index);

    void on_addressHistoryListView_activated(const QModelIndex &index);

    void on_sourceTextEdit_cursorPositionChanged();

private:
    typedef std::unordered_map<std::string, std::string> FileToStringMap_t;
    typedef std::unordered_map<int, const emilpro::IInstruction *> RowToInstruction_t;
    typedef std::unordered_map<uint64_t, int> AddressToRow_t;

    void setupSymbolView();

    void setupInstructionView();

    void setupReferencesView();

    void setupAddressHistoryView();

    void addHistoryEntry(uint64_t addr);

    void refresh();

    void onSymbol(emilpro::ISymbol &sym);

	void updateInstructionView(uint64_t address, const emilpro::ISymbol &sym);

	void updateSymbolView(uint64_t address, const std::string &name = "");

	void updateInfoBox(const emilpro::IInstruction *cur);

    Ui::MainWindow *m_ui;
    QStandardItemModel *m_symbolViewModel;
    QStandardItemModel *m_instructionViewModel;
    QStandardItemModel *m_referencesViewModel;
    QStandardItemModel *m_addressHistoryViewModel;

    void *m_data;
    size_t m_dataSize;
    FileToStringMap_t m_sourceFileMap;
    RowToInstruction_t m_rowToInstruction;
    Highlighter *m_highlighter;
    emilpro::AddressHistory m_addressHistory;

    AddressToRow_t m_addressToSymbolRowMap;
};

#endif // MAINWINDOW_H
