#include "mainwindow.hh"

#include "emilpro/i_disassembler.hh"
#include "ui_mainwindow.h"

#include <QFile>
#include <QMessageBox>
#include <QScrollBar>
#include <QTextBlock>
#include <fmt/format.h>
#include <qstandarditemmodel.h>
#include <string>

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , m_ui(new Ui::MainWindow)
{
}

MainWindow::~MainWindow()
{
    delete m_instruction_view_model;
    delete m_symbol_view_model;
    delete m_ui;
}

void
MainWindow::addHistoryEntry(uint64_t address)
{
}

bool
MainWindow::Init(int argc, char* argv[])
{
    m_ui->setupUi(this);

    SetupSymbolView();
    SetupInstructionView();
    SetupReferencesView();
    SetupAddressHistoryView();
    SetupInstructionEncoding();
    SetupDataView();

    m_highlighter = new Highlighter(m_ui->sourceTextEdit->document());
    QTextEdit::ExtraSelection highlight;
    highlight.cursor = m_ui->sourceTextEdit->textCursor();
    highlight.format.setProperty(QTextFormat::FullWidthSelection, true);
    highlight.format.setBackground(Qt::green);

    QList<QTextEdit::ExtraSelection> extras;
    extras << highlight;
    m_ui->sourceTextEdit->setExtraSelections(extras);

    m_ui->menuBar->setNativeMenuBar(false);

    m_database.ParseFile(argv[1]);

    for (auto& sym_ref : m_database.Symbols())
    {
        auto& sym = sym_ref.get();

        QList<QStandardItem*> lst;

        QString addr = QString::fromStdString(
            fmt::format("0x{:x}", sym.Section().StartAddress() + sym.Offset()));
        QString size = QString::fromStdString(fmt::format("0x{:x}", sym.Size()));
        QString lnk = " ";
        QString r = "R";
        QString w = " "; //sym.isWriteable() ? "W" : " ";
        QString x = " "; //sym.isExecutable() ? "X" : " ";
        QString a = " "; //sym.isAllocated() ? "A" : " ";
        QString name = std::string(sym.GetDemangledName()).c_str();


        lst.append(new QStandardItem(addr));
        lst.append(new QStandardItem(size));
        lst.append(new QStandardItem("")); // linkage
        lst.append(new QStandardItem(r));
        lst.append(new QStandardItem(w));
        lst.append(new QStandardItem(x));
        lst.append(new QStandardItem(a));
        lst.append(new QStandardItem(name));

        m_symbol_view_model->appendRow(lst);
    }
    m_visible_symbols = m_database.Symbols();

    return true;
}


void
MainWindow::on_action_About_triggered(bool activated)
{
    QString title = "About EmilPRO";
    QString text =
        "<center><b>EmilPRO</b></center><br>"
        "<center>5 - \"Märsön\"</center><br><br>"
        "This application needs your help! Visit the webpage for more info and tasks to do!<br>"
        "<center><A "
        "HERF=\"https://github.com/SimonKagstrom/emilpro\">github.com/SimonKagstrom/emilpro</"
        "A><br>";
    QMessageBox about;
    about.setWindowTitle(title);
    about.setText(text);
    about.setIconPixmap(QPixmap(":/images/logo.png"));
    about.exec();
}

void
MainWindow::on_action_Backward_triggered(bool activated)
{
}

void
MainWindow::on_action_Forward_triggered(bool activated)
{
}

void
MainWindow::on_action_Mangle_names_triggered(bool activated)
{
}

void
MainWindow::on_action_Open_triggered(bool activated)
{
}

void
MainWindow::on_action_Quit_triggered(bool activated)
{
    QApplication::quit();
}

void
MainWindow::on_action_Refresh_triggered(bool activated)
{
    on_action_Open_triggered(true);
}

void
MainWindow::on_action_Toggle_data_instructions_triggered(bool activated)
{
    m_ui->tabWidget->setCurrentIndex(!m_ui->tabWidget->currentIndex());
}

void
MainWindow::on_actionAT_T_syntax_x86_triggered(bool activated)
{
}

void
MainWindow::on_addressHistoryListView_activated(const QModelIndex& index)
{
}

void
MainWindow::on_insnCurrentChanged(const QModelIndex& index, const QModelIndex& previous)
{
    auto row = index.row();
    if (row < 0 || row >= m_visible_instructions.size())
    {
        return;
    }

    auto& insn = m_visible_instructions[row].get();

    // Workaround an UBSAN issue with fmt::format, when fmt::join is used
    std::string encoding;
    for (auto x : insn.Data())
    {
        encoding += fmt::format("{:02x} ", x);
    }
    m_ui->instructionEncodingLine->setText(encoding.c_str());

    auto fl = insn.GetSourceLocation();
    if (fl)
    {
        fmt::print("Source location for {}: {}:{}\n", insn.Offset(), fl->first, fl->second);
        auto& source = LookupSourceFile(fl->first);
        auto line = fl->second == 0 ? 0 : fl->second - 1;

        if (source != m_current_source_file)
        {
            m_ui->sourceTextEdit->setText(source);
        }
        if (source != "")
        {
            QTextCursor cursor(m_ui->sourceTextEdit->document()->findBlockByLineNumber(line));
            cursor.select(QTextCursor::LineUnderCursor);
            m_ui->sourceTextEdit->setTextCursor(cursor);
        }
    }
}

void
MainWindow::on_instructionTableView_activated(const QModelIndex& index)
{
}

void
MainWindow::on_instructionTableView_doubleClicked(const QModelIndex& index)
{
    auto row = index.row();
    if (row < 0 || row >= m_visible_instructions.size())
    {
        return;
    }

    auto& insn = m_visible_instructions[row].get();

    auto refers_to = insn.RefersTo();
    if (refers_to)
    {
        uint64_t offset = 0;
        auto sym = refers_to->symbol;
        if (sym)
        {
            auto& section = sym->Section();

            m_visible_instructions = section.Instructions();
            offset = sym->Offset();
        }
        else
        {
            auto lookup_result = m_database.LookupByAddress(&insn.Section(), refers_to->offset);

            for (auto& result : lookup_result)
            {
                auto& section = result.section;

                m_visible_instructions = section.Instructions();
                offset = result.offset;
            }
        }

        UpdateInstructionView(offset);
    }
}

void
MainWindow::on_locationLineEdit_textChanged(const QString& text)
{
}

void
MainWindow::on_locationLineEdit_returnPressed()
{
}

void
MainWindow::on_referencesTableView_activated(const QModelIndex& index)
{
}

void
MainWindow::on_sourceTextEdit_cursorPositionChanged()
{
}

void
MainWindow::on_symbolTableView_activated(const QModelIndex& index)
{
    auto row = index.row();

    if (row < 0 || row >= m_visible_symbols.size())
    {
        return;
    }

    auto& sym = m_visible_symbols[row].get();
    auto& section = sym.Section();

    m_visible_instructions = section.Instructions();
    UpdateInstructionView(sym.Offset());
}

void
MainWindow::on_symbolTableView_entered(const QModelIndex& index)
{
}

void
MainWindow::on_symbolTimerTriggered()
{
}

void
MainWindow::refresh()
{
}

void
MainWindow::restoreState()
{
}

void
MainWindow::saveState()
{
}

void
MainWindow::SetupAddressHistoryView()
{
}

void
MainWindow::SetupDataView()
{
}

void
MainWindow::SetupInfoBox()
{
}

void
MainWindow::SetupInstructionEncoding()
{
}

void
MainWindow::SetupInstructionLabels()
{
    QStringList labels;

    labels << "Address" << "B" << "Instruction" << "F" << "Target";

    m_instruction_view_model->setHorizontalHeaderLabels(labels);
}

void
MainWindow::SetupInstructionView()
{
    m_instruction_view_model = new QStandardItemModel(0, 5, this);

    m_instruction_view_model->setHorizontalHeaderItem(0, new QStandardItem(QString("Address")));
    m_instruction_view_model->setHorizontalHeaderItem(1, new QStandardItem(QString("B")));
    m_instruction_view_model->setHorizontalHeaderItem(2, new QStandardItem(QString("Instruction")));
    m_instruction_view_model->setHorizontalHeaderItem(3, new QStandardItem(QString("F")));
    m_instruction_view_model->setHorizontalHeaderItem(4, new QStandardItem(QString("Target")));

    //    m_ui->instructionTableView->setItemDelegateForColumn(1, &m_backwardItemDelegate);
    //    m_ui->instructionTableView->setItemDelegateForColumn(3, &m_forwardItemDelegate);

    m_ui->instructionTableView->setModel(m_instruction_view_model);
    m_ui->instructionTableView->horizontalHeader()->setStretchLastSection(true);
    m_ui->instructionTableView->resizeColumnsToContents();

    m_ui->instructionTableView->setColumnWidth(0, 100);
    m_ui->instructionTableView->setColumnWidth(1, 80);
    m_ui->instructionTableView->setColumnWidth(2, 300);
    m_ui->instructionTableView->setColumnWidth(3, 80);

    connect(m_ui->instructionTableView->selectionModel(),
            SIGNAL(currentChanged(QModelIndex, QModelIndex)),
            this,
            SLOT(on_insnCurrentChanged(QModelIndex, QModelIndex)));

    SetupInstructionLabels();
}

void
MainWindow::SetupReferencesView()
{
    m_references_view_model = new QStandardItemModel(0, 2, this);

    m_ui->referencesTableView->setModel(m_references_view_model);
    m_ui->referencesTableView->setColumnWidth(0, 80);
    m_ui->referencesTableView->horizontalHeader()->setStretchLastSection(true);
}

void
MainWindow::SetupSymbolView()
{
    m_symbol_view_model = new QStandardItemModel(0, 8, this);
    m_symbol_view_model->setHorizontalHeaderItem(0, new QStandardItem(QString("Address")));
    m_symbol_view_model->setHorizontalHeaderItem(1, new QStandardItem(QString("Size")));
    m_symbol_view_model->setHorizontalHeaderItem(2, new QStandardItem(QString("Lnk")));
    m_symbol_view_model->setHorizontalHeaderItem(3, new QStandardItem(QString("R")));
    m_symbol_view_model->setHorizontalHeaderItem(4, new QStandardItem(QString("W")));
    m_symbol_view_model->setHorizontalHeaderItem(5, new QStandardItem(QString("X")));
    m_symbol_view_model->setHorizontalHeaderItem(6, new QStandardItem(QString("A")));
    m_symbol_view_model->setHorizontalHeaderItem(7, new QStandardItem(QString("Symbol name")));
    m_ui->symbolTableView->setModel(m_symbol_view_model);
    m_ui->symbolTableView->horizontalHeader()->setStretchLastSection(true);
    m_ui->symbolTableView->resizeColumnsToContents();
    m_ui->symbolTableView->setColumnWidth(0, 100);
    m_ui->symbolTableView->setColumnWidth(1, 80);
    m_ui->symbolTableView->setSelectionMode(QAbstractItemView::SingleSelection);
}


void
MainWindow::UpdateSymbolView(uint64_t address, const std::string& name)
{
}

void
MainWindow::UpdateInstructionView(uint64_t offset)
{
    m_instruction_view_model->removeRows(0, m_instruction_view_model->rowCount());
    auto row = 0;

    for (auto& ref : m_visible_instructions)
    {
        auto& ri = ref.get();
        auto& section = ri.Section();

        auto refers_to = ri.RefersTo();

        QList<QStandardItem*> lst;
        lst.append(
            new QStandardItem(fmt::format("{:08x}", section.StartAddress() + ri.Offset()).c_str()));
        lst.append(new QStandardItem(ri.ReferredBy().empty() ? "" : "->"));
        lst.append(new QStandardItem(std::string(ri.AsString()).c_str()));
        lst.append(new QStandardItem(refers_to == std::nullopt ? "" : "->"));
        if (refers_to && refers_to->symbol)
        {
            lst.append(
                new QStandardItem(std::string(refers_to->symbol->GetDemangledName()).c_str()));
        }
        else
        {
            lst.append(new QStandardItem(""));
        }


        if (ri.Offset() == offset)
        {
            row = m_instruction_view_model->rowCount();
        }

        m_instruction_view_model->appendRow(lst);
    }

    m_ui->instructionTableView->selectRow(row);
}

void
MainWindow::UpdateDataView(uint64_t address, size_t size)
{
}

void
MainWindow::UpdatePreferences()
{
}

const QString&
MainWindow::LookupSourceFile(std::string_view path)
{
    auto it = m_source_file_map.find(std::string());
    auto sp = std::string(path);

    if (it == m_source_file_map.end())
    {
        QFile f(sp.c_str());

        if (f.open(QFile::ReadOnly | QFile::Text))
        {
            QTextStream in(&f);

            m_source_file_map.emplace(sp, in.readAll());
        }
        else
        {
            m_source_file_map.emplace(sp, "");
        }
    }

    return m_source_file_map[sp];
}
