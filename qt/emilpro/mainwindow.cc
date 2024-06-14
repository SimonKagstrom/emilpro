#include "mainwindow.hh"

#include "emilpro/i_disassembler.hh"
#include "ui_mainwindow.h"

#include <QFile>
#include <QFileDialog>
#include <QMessageBox>
#include <QScrollBar>
#include <QShortcut>
#include <QTextBlock>
#include <fmt/format.h>
#include <qstandarditemmodel.h>
#include <string>

namespace
{

auto kSectionUndefinedColor = QBrush(Qt::lightGray);
auto kSectionCodeColor = QBrush("lightgreen");
auto kSectionDataColor = QBrush("pink");

auto kSymbolUndefinedColor = kSectionUndefinedColor;
auto kSymbolDataColor = kSectionDataColor;
auto kSymbolDynamicDataColor = QBrush("salmon");
auto kSymbolDynamicColor = QBrush("lightgreen");

} // namespace

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , m_ui(new Ui::MainWindow)
    , m_forward_item_delegate(JumpLaneDelegate::Direction::kForward)
    , m_backward_item_delegate(JumpLaneDelegate::Direction::kBackward)
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

    SetupSectionView();
    SetupSymbolView();
    SetupInstructionView();
    SetupReferencesView();
    SetupAddressHistoryView();
    SetupInstructionEncoding();
    SetupDataView();

    // Set focus on the location line edit by default
    m_ui->locationLineEdit->setFocus();

    m_highlighter = new Highlighter(m_ui->sourceTextEdit->document());
    QTextEdit::ExtraSelection highlight;
    highlight.cursor = m_ui->sourceTextEdit->textCursor();
    highlight.format.setProperty(QTextFormat::FullWidthSelection, true);
    highlight.format.setBackground(Qt::green);

    QList<QTextEdit::ExtraSelection> extras;
    extras << highlight;
    m_ui->sourceTextEdit->setExtraSelections(extras);

    m_ui->menuBar->setNativeMenuBar(false);

    if (argc > 1)
    {
        LoadFile(argv[1]);
    }

    return true;
}

void
MainWindow::LoadFile(const std::string& filename)
{
    auto parser = emilpro::IBinaryParser::FromFile(filename);
    if (!parser)
    {
        // for now
        exit(1);
    }
    auto disassembler = emilpro::IDisassembler::CreateFromArchitecture(parser->GetMachine());
    if (!disassembler)
    {
        // for now
        exit(1);
    }


    m_database.ParseFile(std::move(parser), std::move(disassembler));

    for (auto& section_ref : m_database.Sections())
    {
        const auto& section = section_ref.get();
        QList<QStandardItem*> lst;

        QString addr = QString::fromStdString(fmt::format("0x{:x}", section.StartAddress()));
        QString size = QString::fromStdString(fmt::format("0x{:x}", section.Size()));
        QString flags = QString::fromStdString(section.Flags());
        QString name = QString::fromStdString(section.Name());

        lst.append(new QStandardItem(addr));
        lst.append(new QStandardItem(size));
        lst.append(new QStandardItem(flags));
        lst.append(new QStandardItem(name));

        m_section_view_model->appendRow(lst);
        auto last_row = m_section_view_model->rowCount() - 1;

        if (flags.contains("U"))
        {
            SetRowColor(m_section_view_model, last_row, kSectionUndefinedColor);
        }
        else if (flags.contains("C"))
        {
            SetRowColor(m_section_view_model, last_row, kSectionCodeColor);
        }
        else if (flags.contains("D"))
        {
            SetRowColor(m_section_view_model, last_row, kSectionDataColor);
        }

        m_ui->sectionTableView->setCurrentIndex(m_section_view_model->index(0, 0));
    }

    for (auto& sym_ref : m_database.Symbols())
    {
        const auto& sym = sym_ref.get();

        QList<QStandardItem*> lst;

        QString addr = QString::fromStdString(
            fmt::format("0x{:x}", sym.Section().StartAddress() + sym.Offset()));
        QString size = QString::fromStdString(fmt::format("0x{:x}", sym.Size()));
        QString flags = QString::fromStdString(sym.Flags());
        QString section = QString::fromStdString(sym.Section().Name());
        QString name = QString::fromStdString(sym.DemangledName());


        lst.append(new QStandardItem(addr));
        lst.append(new QStandardItem(size));
        lst.append(new QStandardItem(flags));
        lst.append(new QStandardItem(section));
        lst.append(new QStandardItem(name));

        m_symbol_view_model->appendRow(lst);
        auto last_row = m_symbol_view_model->rowCount() - 1;

        if (flags.contains("U"))
        {
            SetRowColor(m_symbol_view_model, last_row, kSymbolUndefinedColor);
        }
        else if (sym.Section().Flags().find("C") != std::string::npos)
        {
            if (flags.contains("D"))
            {
                SetRowColor(m_symbol_view_model, last_row, kSymbolDynamicColor);
            }
        }
        else if (sym.Section().Flags().find("D") != std::string::npos)
        {
            if (flags.contains("D"))
            {
                SetRowColor(m_symbol_view_model, last_row, kSymbolDynamicDataColor);
            }
            else
            {
                SetRowColor(m_symbol_view_model, last_row, kSymbolDataColor);
            }
        }

        m_ui->symbolTableView->setCurrentIndex(m_symbol_view_model->index(0, 0));
    }
    m_visible_symbols = m_database.Symbols();
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
MainWindow::on_action_FocusLocationBar_triggered(bool activated)
{
    m_ui->locationLineEdit->setFocus();
}


void
MainWindow::on_action_Mangle_names_triggered(bool activated)
{
}

void
MainWindow::on_action_Open_triggered(bool activated)
{
    auto filename = QFileDialog::getOpenFileName(this, tr("Open binary"));

    LoadFile(filename.toStdString());
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
    //m_ui->tabWidget->setCurrentIndex(!m_ui->tabWidget->currentIndex());
}

void
MainWindow::on_actionAT_T_syntax_x86_triggered(bool activated)
{
}

void
MainWindow::on_addressHistoryListView_activated(const QModelIndex& index)
{
    auto entry_index = index.row();
    if (entry_index < 0 || entry_index >= m_address_history.Entries().size())
    {
        return;
    }

    m_address_history.SetIndex(entry_index);
    const auto& entry = m_address_history.Entries()[entry_index];
    auto lookup_result =
        m_database.LookupByAddress(entry.section, entry.section->StartAddress() + entry.offset);
    for (const auto& result : lookup_result)
    {
        if (auto sym_ref = result.symbol; sym_ref)
        {
            const auto& sym = sym_ref->get();

            m_visible_instructions = sym.Instructions();
            UpdateInstructionView(sym, sym.Offset());
            UpdateSymbolView(sym);
        }
    }
}

void
MainWindow::on_insnCurrentChanged(const QModelIndex& index, const QModelIndex& previous)
{
    auto row = index.row();
    if (row < 0 || row >= m_visible_instructions.size())
    {
        return;
    }

    const auto& insn = m_visible_instructions[row].get();

    // Workaround an UBSAN issue with fmt::format, when fmt::join is used
    std::string encoding;
    for (auto x : insn.Data())
    {
        encoding += fmt::format("{:02x} ", x);
    }
    m_ui->instructionEncodingLine->setText(encoding.c_str());

    m_instruction_item_delegate.HighlightStrings(insn.UsedRegisters());

    if (auto fl = insn.GetSourceLocation(); fl)
    {
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

    // Force a repaint with the new register colors
    emit m_instruction_view_model->layoutChanged();
}

void
MainWindow::on_instructionTableView_activated(const QModelIndex& index)
{
    on_instructionTableView_doubleClicked(index);
}

void
MainWindow::on_instructionTableView_doubleClicked(const QModelIndex& index)
{
    auto row = index.row();
    if (row < 0 || row >= m_visible_instructions.size())
    {
        return;
    }

    const auto& insn = m_visible_instructions[row].get();

    auto refers_to = insn.RefersTo();
    if (!refers_to)
    {
        return;
    }

    if (refers_to->symbol)
    {
        auto sym = refers_to->symbol;

        m_visible_instructions = sym->Instructions();
        UpdateInstructionView(*sym, sym->Offset());
        UpdateSymbolView(*sym);
    }
    else
    {
        auto lookup_result = m_database.LookupByAddress(&insn.Section(), refers_to->offset);

        for (const auto& result : lookup_result)
        {
            auto& section = result.section;

            if (auto sym_ref = result.symbol; sym_ref)
            {
                const auto& sym = sym_ref->get();

                m_visible_instructions = sym.Instructions();
                UpdateInstructionView(sym, result.offset + section.StartAddress());
                UpdateSymbolView(sym);
            }
        }
    }
}

void
MainWindow::on_locationLineEdit_textChanged(const QString& text)
{
    auto is_address = false;
    auto address = text.toULongLong(&is_address, 16);

    unsigned lowest_visible = m_symbol_view_model->rowCount() - 1;

    // Hide all symbols which does not match the text / address
    for (auto i = 0u; i < m_symbol_view_model->rowCount(); i++)
    {
        QString to_compare;
        const auto& sym = m_visible_symbols[i].get();

        // Compare either addresses, or symbol names
        if (is_address)
        {
            to_compare = QString::number(sym.Section().StartAddress() + sym.Offset(), 16);
        }
        else
        {
            to_compare = QString(sym.DemangledName().c_str());
        }

        // Ignore underscores and colons, unless explicitly given in the search string
        if (!text.contains("_"))
        {
            to_compare.remove("_");
        }
        if (!text.contains(":"))
        {
            to_compare.remove(":");
        }

        if (to_compare.contains(text, Qt::CaseInsensitive) || m_current_symbol == &sym)
        {
            m_ui->symbolTableView->showRow(i);

            lowest_visible = std::min(lowest_visible, i);
        }
        else
        {
            m_ui->symbolTableView->hideRow(i);
        }
    }

    // ... and focus the first visible line
    m_ui->symbolTableView->setCurrentIndex(m_symbol_view_model->index(lowest_visible, 0));
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

    m_visible_instructions = sym.Instructions();
    UpdateInstructionView(sym, sym.Offset());
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
    m_address_history_view_model = new QStandardItemModel(0, 1, this);

    m_ui->addressHistoryListView->setModel(m_address_history_view_model);
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

    labels << "Address"
           << "B"
           << "Instruction"
           << "F"
           << "Target";

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

    m_ui->instructionTableView->setItemDelegateForColumn(1, &m_backward_item_delegate);
    m_ui->instructionTableView->setItemDelegateForColumn(2, &m_instruction_item_delegate);
    m_ui->instructionTableView->setItemDelegateForColumn(3, &m_forward_item_delegate);

    m_ui->instructionTableView->setModel(m_instruction_view_model);
    m_ui->instructionTableView->horizontalHeader()->setStretchLastSection(true);
    m_ui->instructionTableView->resizeColumnsToContents();

    m_ui->instructionTableView->setColumnWidth(0, 120);
    m_ui->instructionTableView->setColumnWidth(1, 80);
    m_ui->instructionTableView->setColumnWidth(2, 300);
    m_ui->instructionTableView->setColumnWidth(3, 80);

    connect(m_ui->instructionTableView->selectionModel(),
            SIGNAL(currentChanged(QModelIndex, QModelIndex)),
            this,
            SLOT(on_insnCurrentChanged(QModelIndex, QModelIndex)));

    SetupInstructionLabels();

    m_ui->instructionTableView->installEventFilter(this);
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
MainWindow::SetupSectionView()
{
    m_section_view_model = new QStandardItemModel(0, 4, this);
    m_section_view_model->setHorizontalHeaderItem(0, new QStandardItem(QString("Address")));
    m_section_view_model->setHorizontalHeaderItem(1, new QStandardItem(QString("Size")));
    m_section_view_model->setHorizontalHeaderItem(2, new QStandardItem(QString("Flags")));
    m_section_view_model->setHorizontalHeaderItem(3, new QStandardItem(QString("Name")));
    m_ui->sectionTableView->setModel(m_section_view_model);
    m_ui->sectionTableView->horizontalHeader()->setStretchLastSection(true);
    m_ui->sectionTableView->resizeColumnsToContents();
    m_ui->sectionTableView->setColumnWidth(0, 120);
    m_ui->sectionTableView->setColumnWidth(1, 80);
    m_ui->sectionTableView->setColumnWidth(2, 80);
    m_ui->sectionTableView->setSelectionMode(QAbstractItemView::SingleSelection);
}

void
MainWindow::SetupSymbolView()
{
    m_symbol_view_model = new QStandardItemModel(0, 4, this);
    m_symbol_view_model->setHorizontalHeaderItem(0, new QStandardItem(QString("Address")));
    m_symbol_view_model->setHorizontalHeaderItem(1, new QStandardItem(QString("Size")));
    m_symbol_view_model->setHorizontalHeaderItem(2, new QStandardItem(QString("Flags")));
    m_symbol_view_model->setHorizontalHeaderItem(3, new QStandardItem(QString("Section")));
    m_symbol_view_model->setHorizontalHeaderItem(4, new QStandardItem(QString("Symbol name")));
    m_ui->symbolTableView->setModel(m_symbol_view_model);
    m_ui->symbolTableView->horizontalHeader()->setStretchLastSection(true);
    m_ui->symbolTableView->resizeColumnsToContents();
    m_ui->symbolTableView->setColumnWidth(0, 120);
    m_ui->symbolTableView->setColumnWidth(1, 80);
    m_ui->symbolTableView->setColumnWidth(3, 160);
    m_ui->symbolTableView->setSelectionMode(QAbstractItemView::SingleSelection);

    // Install an event filter to have the Enter key behave like activate
    m_ui->symbolTableView->installEventFilter(this);
}


void
MainWindow::UpdateSymbolView(const emilpro::ISymbol& symbol)
{
    unsigned row = 0;

    for (const auto& cur : m_visible_symbols)
    {
        if (&cur.get() == &symbol)
        {
            m_ui->symbolTableView->showRow(row);
            m_ui->symbolTableView->selectRow(row);
            m_ui->symbolTableView->scrollTo(m_symbol_view_model->index(row, 0));
            return;
        }
        row++;
    }
}

void
MainWindow::UpdateInstructionView(const emilpro::ISymbol& symbol, uint64_t offset)
{
    m_address_history.PushEntry(symbol.Section(), offset);
    UpdateHistoryView();

    m_instruction_view_model->removeRows(0, m_instruction_view_model->rowCount());
    auto selected_row = 0;

    m_forward_item_delegate.Update(64, symbol.Instructions());
    m_backward_item_delegate.Update(64, symbol.Instructions());

    for (auto& ref : symbol.Instructions())
    {
        const auto& ri = ref.get();
        const auto& section = ri.Section();

        auto refers_to = ri.RefersTo();

        QList<QStandardItem*> lst;
        lst.append(new QStandardItem(fmt::format("0x{:08x}", ri.Offset()).c_str()));
        lst.append(nullptr); // Backward branch
        lst.append(new QStandardItem(std::string(ri.AsString()).c_str()));
        lst.append(nullptr); // Forward branch
        if (refers_to)
        {
            if (refers_to->symbol)
            {
                lst.append(
                    new QStandardItem(QString::fromStdString(refers_to->symbol->DemangledName())));
            }
            else
            {
                lst.append(new QStandardItem(fmt::format("0x{:08x}", refers_to->offset).c_str()));
            }
        }
        else
        {
            lst.append(nullptr);
        }


        auto cur_row = m_instruction_view_model->rowCount();
        if (ri.Offset() == offset)
        {
            selected_row = cur_row;
        }

        m_instruction_view_model->appendRow(lst);
    }

    m_ui->instructionTableView->selectRow(selected_row);
}

void
MainWindow::UpdateHistoryView()
{
    m_address_history_view_model->removeRows(0, m_address_history_view_model->rowCount());

    for (const auto& entry : m_address_history.Entries())
    {
        auto lookup_result =
            m_database.LookupByAddress(entry.section, entry.section->StartAddress() + entry.offset);

        QString str;

        if (lookup_result.size() > 0 && lookup_result[0].symbol)
        {
            const auto& sym = lookup_result[0].symbol->get();
            str = QString::fromStdString(fmt::format(
                "0x{:x} ({})", entry.section->StartAddress() + entry.offset, sym.DemangledName()));
        }
        else
        {
            str = QString::fromStdString(
                fmt::format("0x{:x}", entry.section->StartAddress() + entry.offset));
        }

        m_address_history_view_model->appendRow(new QStandardItem(str));
    }

    auto idx = m_address_history_view_model->index(m_address_history.CurrentIndex(), 0);
    m_ui->addressHistoryListView->setCurrentIndex(idx);
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

void
MainWindow::SetRowColor(QAbstractItemModel* model,
                        int row,
                        const QBrush& color,
                        const QModelIndex& parent)
{
    assert(model);
    assert(row >= 0 && row < model->rowCount(parent));

    const int colCount = model->columnCount(parent);
    for (int j = 0; j < colCount; ++j)
    {
        model->setData(model->index(row, j, parent), color, Qt::BackgroundRole);
    }
}

bool
MainWindow::eventFilter(QObject* watched, QEvent* event)
{
    // (Thanks to copilot for much of this code!)
    if (event->type() == QEvent::KeyPress)
    {
        QKeyEvent* keyEvent = static_cast<QKeyEvent*>(event);
        if (keyEvent->key() == Qt::Key_Enter || keyEvent->key() == Qt::Key_Return)
        {
            auto p = watched == m_ui->symbolTableView ? m_ui->symbolTableView
                                                      : m_ui->instructionTableView;

            // Get the current index
            QModelIndex currentIndex = p->currentIndex();
            if (currentIndex.isValid())
            {
                // Emit the activated signal with the current index
                emit p->activated(currentIndex);
                return true; // Indicate that the event was handled
            }
        }
    }

    return QMainWindow::eventFilter(watched, event); // Pass the event on to the base class
}