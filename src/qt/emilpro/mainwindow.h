#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <qstandarditemmodel.h>

#include <model.hh>
#include <symbolfactory.hh>

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

private:
    typedef std::unordered_map<std::string, std::string> FileToStringMap_t;
    typedef std::unordered_map<int, const emilpro::IInstruction *> RowToInstruction_t;

    void setupSymbolView();

    void setupInstructionView();

    void setupReferencesView();

    void refresh();

    void onSymbol(emilpro::ISymbol &sym);

	void updateInstructionView(uint64_t address, const emilpro::ISymbol &sym);

    Ui::MainWindow *m_ui;
    QStandardItemModel *m_symbolViewModel;
    QStandardItemModel *m_instructionViewModel;
    QStandardItemModel *m_referencesViewModel;

    void *m_data;
    size_t m_dataSize;
    FileToStringMap_t m_sourceFileMap;
    RowToInstruction_t m_rowToInstruction;
    Highlighter *m_highlighter;
};

#endif // MAINWINDOW_H
