#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "jumpdisplay-delegate.h"

#include <emilpro.hh>
#include <configuration.hh>
#include <model.hh>
#include <utils.hh>
#include <ui-helpers.hh>

#include <qstandarditemmodel.h>
#include <QTextBlock>
#include <QScrollBar>

using namespace emilpro;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    m_ui(new Ui::MainWindow),
    m_data(NULL),
    m_dataSize(0),
    m_backwardItemDelegate(false),
    m_forwardItemDelegate(true)
{
    m_ui->setupUi(this);

    setupSymbolView();

    setupInstructionView();

    setupReferencesView();

    setupAddressHistoryView();


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

	updateSymbolView(string_to_integer(s), name);
}

void MainWindow::refresh()
{
	Configuration &conf = Configuration::instance();
	std::string file = conf.getFileName();
	Model &model = Model::instance();

	delete m_symbolViewModel;
	m_addressToSymbolRowMap.clear();
	setupSymbolView();

	if (file != "") {
		m_data = read_file(&m_dataSize, "%s", file.c_str());
		if (!m_data) {
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

    m_addressToSymbolRowMap[sym.getAddress()] = m_symbolViewModel->rowCount();

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

    m_ui->instructionTableView->setItemDelegateForColumn(1, &m_backwardItemDelegate);
    m_ui->instructionTableView->setItemDelegateForColumn(3, &m_forwardItemDelegate);

    m_ui->instructionTableView->setModel(m_instructionViewModel);
    m_ui->instructionTableView->horizontalHeader()->setStretchLastSection(true);

    m_ui->instructionTableView->setColumnWidth(0, 100);
    m_ui->instructionTableView->setColumnWidth(1, 80);
    m_ui->instructionTableView->setColumnWidth(2, 300);
    m_ui->instructionTableView->setColumnWidth(3, 80);

    setupInstructionLabels();
}

void MainWindow::setupReferencesView()
{
    m_referencesViewModel = new QStandardItemModel(0, 1, this);
    m_referencesViewModel->setHorizontalHeaderItem(0, new QStandardItem(QString("Symbol references")));

    m_ui->referencesListView->setModel(m_referencesViewModel);
}

void MainWindow::setupInstructionLabels()
{
    QStringList labels;

    labels << "Address"
    	<< "B"
    	<< "Instruction"
    	<< "F"
    	<< "Target";

    m_instructionViewModel->setHorizontalHeaderLabels(labels);
}

void MainWindow::updateInstructionView(uint64_t address, const ISymbol& sym)
{
	Model &model = Model::instance();
	InstructionList_t insns = model.getInstructions(sym.getAddress(), sym.getAddress() + sym.getSize());
	int row = 0;

	m_instructionViewModel->clear();
	setupInstructionLabels();

	m_rowToInstruction.clear();
	m_forwardItemDelegate.update(insns, 60);
	m_backwardItemDelegate.update(insns, 60);

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

		if (cur->getBranchTargetAddress() != IInstruction::INVALID_ADDRESS) {
			uint64_t targetAddress = cur->getBranchTargetAddress();
			Model::SymbolList_t targetSyms = model.getSymbolExact(targetAddress);

			if (targetSyms.empty() || (targetAddress >= sym.getAddress() && targetAddress < sym.getAddress() + sym.getSize())) {
				target = QString::fromStdString(fmt("0x%0llx", (long long)targetAddress));
			} else {
				const ISymbol *targetSym = targetSyms.front();

				target = QString::fromStdString(targetSym->getName());
			}
		}


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
	int row = index.row();
	QModelIndex parent = index.parent();

	std::string s = m_instructionViewModel->data(m_instructionViewModel->index(row, 0, parent)).toString().toStdString();
	if (!string_is_integer(s))
		return;

	Model &model = Model::instance();
	uint64_t address = string_to_integer(s);

	const IInstruction *cur = model.getInstructionByAddress(address);

	if (!cur)
		return;

	if (cur->getType() != IInstruction::IT_CFLOW && cur->getType() != IInstruction::IT_CALL)
		return;

	uint64_t target = cur->getBranchTargetAddress();

	if (target == IInstruction::INVALID_ADDRESS)
		return;

	// Lookup symbol for this instruction
	const Model::SymbolList_t syms = model.getNearestSymbol(cur->getAddress());
	if (syms.size() == 0)
		return;

	for (Model::SymbolList_t::const_iterator sIt = syms.begin();
			sIt != syms.end();
			++sIt) {
		const ISymbol *sym = *sIt;

		if (sym->getType() != ISymbol::SYM_TEXT)
			continue;

		addHistoryEntry(target);

		// Follow links within the function or to another function
		if (target >= sym->getAddress() && target < sym->getAddress() + sym->getSize()) {
			// FIXME! NYI within function
			printf("Jump within function (0x%llx...0x%llx dst 0x%llx)\n",
					(unsigned long long)sym->getAddress(), (unsigned long long)(sym->getAddress() + sym->getSize()),
					(unsigned long long)target);
		} else {
			updateSymbolView(target);
		}
	}


	//addHistoryEntry(addr);
}

void MainWindow::on_instructionTableView_entered(const QModelIndex &index)
{
	int row = index.row();

	const IInstruction *cur = m_rowToInstruction[row];

	if (!cur)
		return;
	updateInfoBox(cur);

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
	m_ui->sourceTextEdit->setTextCursor(cursor);

    QTextEdit::ExtraSelection highlight;
    highlight.cursor = m_ui->sourceTextEdit->textCursor();
    highlight.format.setProperty(QTextFormat::FullWidthSelection, true);
    highlight.format.setBackground( Qt::green );

    QList<QTextEdit::ExtraSelection> extras;
    extras << highlight;
    m_ui->sourceTextEdit->setExtraSelections( extras );
}

void MainWindow::on_referencesListView_activated(const QModelIndex &index)
{
	//addHistoryEntry(addr);
}

void MainWindow::on_symbolTableView_entered(const QModelIndex &index)
{
	int row = index.row();
	QModelIndex parent = index.parent();

	std::string s = m_symbolViewModel->data(m_symbolViewModel->index(row, 0, parent)).toString().toStdString();

	m_referencesViewModel->clear();

	if (!string_is_integer(s, 16))
		return;

	Model &model = Model::instance();

	uint64_t address = string_to_integer(s);

	const Model::CrossReferenceList_t &references = model.getReferences(address);

	for (Model::CrossReferenceList_t::const_iterator it = references.begin();
			it != references.end();
			++it) {
		uint64_t cur = *it;
		const Model::SymbolList_t syms = model.getNearestSymbol(cur);

		if (syms.empty()) {
			QString name = QString::fromStdString(s);

			m_referencesViewModel->appendRow(new QStandardItem(name));
		} else {
			for (Model::SymbolList_t::const_iterator sIt = syms.begin();
					sIt != syms.end();
					++sIt) {
				ISymbol *sym = *sIt;
				// FIXME! Mr Gorbachev, mangle this name!
				QString name = QString::fromStdString(sym->getName());

				m_referencesViewModel->appendRow(new QStandardItem(name));
			}
		}
	}
}


void MainWindow::setupAddressHistoryView()
{
    m_addressHistoryViewModel = new QStandardItemModel(0, 1, this);

    m_ui->addressHistoryListView->setModel(m_addressHistoryViewModel);
}


void MainWindow::on_addressHistoryListView_activated(const QModelIndex &index)
{
}


void MainWindow::addHistoryEntry(uint64_t address)
{
	Model &model = Model::instance();
	bool res = m_addressHistory.maybeAddEntry(address);

	if (!res)
		return;

	const Model::SymbolList_t syms = model.getNearestSymbol(address);

	const ISymbol *p = NULL;
	for (Model::SymbolList_t::const_iterator sIt = syms.begin();
			sIt != syms.end();
			++sIt) {
		const ISymbol *sym = *sIt;

		if (sym->getType() != ISymbol::SYM_TEXT)
			continue;
		p = sym;
	}

	std::string symName = "";

	if (p)
		symName = p->getName();

	QString str = QString::fromStdString(fmt("0x%0llx%s%s%s",
			(unsigned long long)address,
			p ? " (" : "",
			symName.c_str(),
			p ? ")" : ""));

	m_addressHistoryViewModel->appendRow(new QStandardItem(str));
}

void MainWindow::updateSymbolView(uint64_t address, const std::string &name)
{
	const ISymbol *sym = UiHelpers::getBestSymbol(address, name);

	if (!sym)
		return;

	addHistoryEntry(address);
	if (m_addressToSymbolRowMap.find(sym->getAddress()) != m_addressToSymbolRowMap.end())
		m_ui->symbolTableView->selectRow(m_addressToSymbolRowMap[sym->getAddress()]);

	updateInstructionView(address, *sym);
}

void MainWindow::on_sourceTextEdit_cursorPositionChanged()
{
	int cursorY = m_ui->sourceTextEdit->cursorRect().top();

	QScrollBar *vbar = m_ui->sourceTextEdit->verticalScrollBar();

	vbar->setValue(vbar->value() + cursorY - m_ui->sourceTextEdit->height() / 2);
}

void MainWindow::updateInfoBox(const emilpro::IInstruction* insn)
{
	if (!insn) {
		m_ui->instructionTextEdit->setText("No instruction");
		return;
	}

	QString s = QString::fromStdString(UiHelpers::getInstructionInfoString(*insn));

	m_ui->instructionTextEdit->setText(s);
}
