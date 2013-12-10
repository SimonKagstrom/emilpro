#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <qstandarditemmodel.h>

#include <model.hh>
#include <symbolfactory.hh>

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

private:
    void setupSymbolView();

    void refresh();

    void onSymbol(emilpro::ISymbol &sym);

	void updateInstructionView(uint64_t address, const emilpro::ISymbol &sym);


    Ui::MainWindow *m_ui;
    QStandardItemModel *m_symbolViewModel;
    QStandardItemModel *m_instructionViewModel;

    void *m_data;
    size_t m_dataSize;
};

#endif // MAINWINDOW_H
