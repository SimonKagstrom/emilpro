#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <qstandarditemmodel.h>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    m_ui(new Ui::MainWindow)
{
    m_ui->setupUi(this);

    m_symbolViewModel = new QStandardItemModel(0,8,this);
    m_symbolViewModel->setHorizontalHeaderItem(0, new QStandardItem(QString("Address")));
    m_symbolViewModel->setHorizontalHeaderItem(1, new QStandardItem(QString("Size")));
    m_symbolViewModel->setHorizontalHeaderItem(2, new QStandardItem(QString("Lnk")));
    m_symbolViewModel->setHorizontalHeaderItem(3, new QStandardItem(QString("R")));
    m_symbolViewModel->setHorizontalHeaderItem(4, new QStandardItem(QString("W")));
    m_symbolViewModel->setHorizontalHeaderItem(5, new QStandardItem(QString("X")));
    m_symbolViewModel->setHorizontalHeaderItem(6, new QStandardItem(QString("A")));
    m_symbolViewModel->setHorizontalHeaderItem(7, new QStandardItem(QString("Symbol name")));

    m_instructionViewModel = new QStandardItemModel(0,5,this);
    m_instructionViewModel->setHorizontalHeaderItem(0, new QStandardItem(QString("Address")));
    m_instructionViewModel->setHorizontalHeaderItem(1, new QStandardItem(QString("B")));
    m_instructionViewModel->setHorizontalHeaderItem(2, new QStandardItem(QString("Instruction")));
    m_instructionViewModel->setHorizontalHeaderItem(3, new QStandardItem(QString("F")));
    m_instructionViewModel->setHorizontalHeaderItem(4, new QStandardItem(QString("Target")));

    QStandardItemModel *a = new QStandardItemModel(0, 1, this);
    a->setHorizontalHeaderItem(0, new QStandardItem(QString("Symbol references")));

    m_ui->referencesListView->setModel(a);

    m_ui->symbolTableView->setModel(m_symbolViewModel);
    m_ui->instructionTableView->setModel(m_instructionViewModel);

    m_ui->symbolTableView->horizontalHeader()->setStretchLastSection(true);
    m_ui->symbolTableView->resizeColumnsToContents();
    m_ui->instructionTableView->horizontalHeader()->setStretchLastSection(true);
    m_ui->instructionTableView->resizeColumnsToContents();
}

MainWindow::~MainWindow()
{
    delete m_instructionViewModel;
    delete m_symbolViewModel;
    delete m_ui;
}

void MainWindow::on_symbolTableView_activated(const QModelIndex &index)
{
}
