#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <qstandarditemmodel.h>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT
    
public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    
private slots:
    void on_symbolTableView_activated(const QModelIndex &index);

private:
    Ui::MainWindow *m_ui;
    QStandardItemModel *m_symbolViewModel;
    QStandardItemModel *m_instructionViewModel;
};

#endif // MAINWINDOW_H
