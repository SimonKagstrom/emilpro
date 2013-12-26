#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <emilpro.hh>
#include <configuration.hh>
#include <model.hh>
#include <utils.hh>
#include <ui-helpers.hh>

#include <qstandarditemmodel.h>
#include <QTextBlock>

using namespace emilpro;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    m_ui(new Ui::MainWindow),
    m_data(NULL),
    m_dataSize(0)
{
    m_ui->setupUi(this);

    setupSymbolView();

    setupInstructionView();

    QStandardItemModel *a = new QStandardItemModel(0, 1, this);
    a->setHorizontalHeaderItem(0, new QStandardItem(QString("Symbol references")));

    m_ui->referencesListView->setModel(a);

    m_highlighter = new Highlighter(m_ui->sourceTextEdit->document());

	Model::instance().registerSymbolListener(this);
}

MainWindow::~MainWindow()
{
    delete m_instructionViewModel;
    delete m_symbolViewModel;
    delete m_ui;
}

bool MainWindow::init(int argc, char* argv[])
{
	EmilPro::init();

	Configuration &conf = Configuration::instance();

	if (conf.parse(argc, (const char **)argv) != true)
		return false;

	refresh();

	return true;
}

void MainWindow::on_symbolTableView_activated(const QModelIndex &index)
{
	int row = index.row();
	QModelIndex parent = index.parent();

	std::string s = m_symbolViewModel->data(m_symbolViewModel->index(row, 0, parent)).toString().toStdString();
	std::string name = m_symbolViewModel->data(m_symbolViewModel->index(row, 7, parent)).toString().toStdString();

	if (!string_is_integer(s))
		return;

	uint64_t addr = string_to_integer(s);
	Model &model = Model::instance();

	const ISymbol *sym = UiHelpers::getBestSymbol(addr, name);

	if (!sym)
		return;

	updateInstructionView(addr, *sym);
}

void MainWindow::refresh()
{
	Configuration &conf = Configuration::instance();
	std::string file = conf.getFileName();
	Model &model = Model::instance();

	delete m_symbolViewModel;
	setupSymbolView();

	if (file != "") {
		m_data = read_file(&m_dataSize, "%s", file.c_str());
		if (m_data) {
			model.addData(m_data, m_dataSize);
		} else {
			error("Can't read %s, exiting", file.c_str());
			exit(1);
		}

		model.addData(m_data, m_dataSize);
		model.parseAll();
	}
}

void MainWindow::onSymbol(ISymbol& sym)
{
	// Skip the file symbol
	if (sym.getType() == ISymbol::SYM_FILE)
		return;

	printf("XXX: 0x%08x: %s at %p\n", sym.getAddress(), sym.getName().c_str(), &sym);

    QList<QStandardItem *> lst;

    QString addr = QString::fromStdString(fmt("0x%llx", (unsigned long long)sym.getAddress()));
    QString size = QString::fromStdString(fmt("0x%llx", (unsigned long long)sym.getSize()));
    QString lnk = sym.getLinkage() == ISymbol::LINK_DYNAMIC ? "D" : " ";
    QString r = "R";
    QString w = sym.isWriteable() ? "W" : " ";
    QString x = sym.isExecutable() ? "X" : " ";
    QString a = sym.isAllocated() ? "A" : " ";
    QString name = QString::fromStdString(sym.getName());

    lst.append(new QStandardItem(addr));
    lst.append(new QStandardItem(size));
    lst.append(new QStandardItem(lnk));
    lst.append(new QStandardItem(r));
    lst.append(new QStandardItem(w));
    lst.append(new QStandardItem(x));
    lst.append(new QStandardItem(a));
    lst.append(new QStandardItem(name));
    m_symbolViewModel->appendRow(lst);
    m_ui->symbolTableView->resizeColumnsToContents();
}

void MainWindow::setupSymbolView()
{
    m_symbolViewModel = new QStandardItemModel(0,8,this);
    m_symbolViewModel->setHorizontalHeaderItem(0, new QStandardItem(QString("Address")));
    m_symbolViewModel->setHorizontalHeaderItem(1, new QStandardItem(QString("Size")));
    m_symbolViewModel->setHorizontalHeaderItem(2, new QStandardItem(QString("Lnk")));
    m_symbolViewModel->setHorizontalHeaderItem(3, new QStandardItem(QString("R")));
    m_symbolViewModel->setHorizontalHeaderItem(4, new QStandardItem(QString("W")));
    m_symbolViewModel->setHorizontalHeaderItem(5, new QStandardItem(QString("X")));
    m_symbolViewModel->setHorizontalHeaderItem(6, new QStandardItem(QString("A")));
    m_symbolViewModel->setHorizontalHeaderItem(7, new QStandardItem(QString("Symbol name")));
    m_ui->symbolTableView->setModel(m_symbolViewModel);
    m_ui->symbolTableView->horizontalHeader()->setStretchLastSection(true);
    m_ui->symbolTableView->resizeColumnsToContents();
}

void MainWindow::setupInstructionView()
{
    m_instructionViewModel = new QStandardItemModel(0,5,this);
    m_instructionViewModel->setHorizontalHeaderItem(0, new QStandardItem(QString("Address")));
    m_instructionViewModel->setHorizontalHeaderItem(1, new QStandardItem(QString("B")));
    m_instructionViewModel->setHorizontalHeaderItem(2, new QStandardItem(QString("Instruction")));
    m_instructionViewModel->setHorizontalHeaderItem(3, new QStandardItem(QString("F")));
    m_instructionViewModel->setHorizontalHeaderItem(4, new QStandardItem(QString("Target")));

    m_ui->instructionTableView->setModel(m_instructionViewModel);

    m_ui->instructionTableView->horizontalHeader()->setStretchLastSection(true);
    m_ui->instructionTableView->resizeColumnsToContents();
}

void MainWindow::updateInstructionView(uint64_t address, const ISymbol& sym)
{
	Model &model = Model::instance();
	InstructionList_t insns = model.getInstructions(sym.getAddress(), sym.getAddress() + sym.getSize());
	int row = 0;

	m_rowToInstruction.clear();
	for (InstructionList_t::iterator it = insns.begin();
			it != insns.end();
			++it, ++row) {
		IInstruction *cur = *it;

		m_rowToInstruction[row] = cur;

		QList<QStandardItem *> lst;

		QString addr = QString::fromStdString(fmt("0x%llx", (unsigned long long)cur->getAddress()));
		QString b = "";
		QString instruction = QString::fromStdString(cur->getString());
		QString f = "";
		QString target;

		QString name = QString::fromStdString(sym.getName());

		lst.append(new QStandardItem(addr));
		lst.append(new QStandardItem(b));
		lst.append(new QStandardItem(instruction));
		lst.append(new QStandardItem(f));
		lst.append(new QStandardItem(target));
		m_instructionViewModel->appendRow(lst);
	}

	m_ui->instructionTableView->resizeColumnsToContents();
}

void MainWindow::on_instructionTableView_activated(const QModelIndex &index)
{
}

void MainWindow::on_instructionTableView_entered(const QModelIndex &index)
{
	int row = index.row();

	const IInstruction *cur = m_rowToInstruction[row];

	if (!cur)
		return;
	ILineProvider::FileLine fileLine = Model::instance().getLineByAddress(cur->getAddress());

	if (!fileLine.m_isValid)
		return;

	if (m_sourceFileMap.find(fileLine.m_file) == m_sourceFileMap.end())
		m_sourceFileMap[fileLine.m_file] = UiHelpers::getFileContents(fileLine.m_file);
	std::string data = m_sourceFileMap[fileLine.m_file];

	m_ui->sourceTextEdit->setText(QString(data.c_str()));
	if (data == "")
		return;

	int line = fileLine.m_lineNr - 1;

	if (line < 0)
		line = 0;

	QTextCursor cursor(m_ui->sourceTextEdit->document()->findBlockByLineNumber(line));
	cursor.select(QTextCursor::LineUnderCursor);
	cursor.movePosition(QTextCursor::Down, QTextCursor::MoveAnchor, 5);
	m_ui->sourceTextEdit->setTextCursor(cursor);

    QTextEdit::ExtraSelection highlight;
    highlight.cursor = m_ui->sourceTextEdit->textCursor();
    highlight.format.setProperty(QTextFormat::FullWidthSelection, true);
    highlight.format.setBackground( Qt::green );

    QList<QTextEdit::ExtraSelection> extras;
    extras << highlight;
    m_ui->sourceTextEdit->setExtraSelections( extras );
}
