#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "jumpdisplay-delegate.h"

#include <emilpro.hh>
#include <configuration.hh>
#include <model.hh>
#include <utils.hh>
#include <ui-helpers.hh>
#include <server.hh>

#include <qstandarditemmodel.h>
#include <QTextBlock>
#include <QScrollBar>


using namespace emilpro;

MainWindow::MainWindow(QWidget *parent) :
    		QMainWindow(parent),
    		m_ui(new Ui::MainWindow),
    		m_addressHistoryDisabled(false),
    		m_backwardItemDelegate(false),
    		m_forwardItemDelegate(true)
{
}

MainWindow::~MainWindow()
{
	delete m_instructionViewModel;
	delete m_symbolViewModel;
	delete m_ui;
}

void MainWindow::addHistoryEntry(uint64_t address)
{
	if (m_addressHistoryDisabled)
		return;

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
		symName = NameMangler::instance().mangle(p->getName());

	QString str = QString::fromStdString(fmt("0x%0llx%s%s%s",
			(unsigned long long)address,
			p ? " (" : "",
					symName.c_str(),
					p ? ")" : ""));

	m_addressHistoryViewModel->appendRow(new QStandardItem(str));

	// Highlight current item
	auto idx = m_addressHistoryViewModel->index(m_addressHistoryViewModel->rowCount() - 1, 0);
	m_ui->addressHistoryListView->setCurrentIndex(idx);
}

void MainWindow::handleSymbol(emilpro::ISymbol& sym)
{
	// Skip the file symbol
	if (sym.getType() == ISymbol::SYM_FILE)
		return;

	QList<QStandardItem *> lst;

	QString addr = QString::fromStdString(fmt("0x%llx", (unsigned long long)sym.getAddress()));
	QString size = QString::fromStdString(fmt("0x%llx", (unsigned long long)sym.getSize()));
	QString lnk = " ";
	QString r = "R";
	QString w = sym.isWriteable() ? "W" : " ";
	QString x = sym.isExecutable() ? "X" : " ";
	QString a = sym.isAllocated() ? "A" : " ";
	QString name = QString::fromStdString(NameMangler::instance().mangle(sym.getName()));

	auto linkage = sym.getLinkage();
	if (linkage == ISymbol::LINK_DYNAMIC)
		lnk = "D";
	else if (linkage == ISymbol::LINK_UNDEFINED)
		lnk = "U";

	lst.append(new QStandardItem(addr));
	lst.append(new QStandardItem(size));
	lst.append(new QStandardItem(lnk));
	lst.append(new QStandardItem(r));
	lst.append(new QStandardItem(w));
	lst.append(new QStandardItem(x));
	lst.append(new QStandardItem(a));
	lst.append(new QStandardItem(name));

	m_addressToSymbolRowMap[fmt("0x%llx_%s", (unsigned long long)sym.getAddress(), sym.getName().c_str())] = m_symbolViewModel->rowCount();

	m_symbolViewModel->appendRow(lst);
}

bool MainWindow::init(int argc, char* argv[])
{
	EmilPro::init();

	m_ui->setupUi(this);

	setupSymbolView();
	setupInstructionView();
	setupReferencesView();
	setupAddressHistoryView();
	setupInstructionEncoding();
	setupDataView();

	m_ui->menuBar->setNativeMenuBar(false);
	m_editInstructionDialog = new EditInstructionDialog();
	m_highlighter = new Highlighter(m_ui->sourceTextEdit->document());

	Model::instance().registerSymbolListener(this);
	NameMangler::instance().registerListener(this);
	Preferences::instance().registerListener("X86InstructionSyntax", this);
	Preferences::instance().registerListener("QtMainWindowSize", this);

	Configuration &conf = Configuration::instance();

	if (conf.parse(argc, (const char **)argv) != true)
		return false;

	Server::instance().connect();

	std::string file = conf.getFileName();
	Model &model = Model::instance();

	if (file != "") {
		m_data = read_file(&m_dataSize, "%s", file.c_str());
		if (!m_data) {
			error("Can't read %s, exiting", file.c_str());
			exit(1);
		}

		model.addData(m_data, m_dataSize);
		model.parseAll();
	}

	return true;
}

void MainWindow::loadData()
{
	Model &model = Model::instance();
	model.addData(m_data, m_dataSize);
	model.parseAll();
	refresh();
}

void MainWindow::on_action_About_triggered(bool activated)
{
	QString title = "About EmilPRO";
	QString text = "<center><b>EmilPRO</b></center><br>"
			"<center>4 - \"Bräkne Hoby\"</center><br><br>"
			"This application needs your help! Visit the webpage for more info and tasks to do!<br>"
			"<center><A HERF=\"http://www.emilpro.com\">www.emilpro.com</A><br>";
	QMessageBox about;
	about.setWindowTitle(title);
	about.setText(text);
	about.setIconPixmap(QPixmap(":/images/logo.png"));
	about.exec();
}

void MainWindow::on_action_Backward_triggered(bool activated)
{
	updateHistoryEntry(m_addressHistory.back());
}

void MainWindow::on_action_Forward_triggered(bool activated)
{
	updateHistoryEntry(m_addressHistory.forward());
}

void MainWindow::on_action_Mangle_names_triggered(bool activated)
{
	bool isActive = m_ui->action_Mangle_names->isChecked();

	std::string value = isActive ? "yes" : "no";

	Preferences::instance().setValue("MangleNames", value);
}

void MainWindow::on_action_Open_triggered(bool activated)
{
	// open and read file, if fileName is not empty we're doing a refresh
	if (fileName.isEmpty())
		fileName = QFileDialog::getOpenFileName(this, tr("Open binary"));

	if (fileName.isEmpty())
		return;

	m_data = read_file(&m_dataSize, "%s", fileName.toStdString().c_str());
	if (!m_data) {
		error("Can't read %s, exiting", fileName.toStdString().c_str());
		exit(1);
	}

	MainWindow::setWindowTitle(fileName);

	loadData();
}

void MainWindow::on_action_Quit_triggered(bool activated)
{
	QApplication::quit();
}

void MainWindow::on_action_Refresh_triggered(bool activated)
{
	saveState();
	on_action_Open_triggered(true);
}

void MainWindow::on_action_Toggle_data_instructions_triggered(bool activated)
{
	m_ui->tabWidget->setCurrentIndex(!m_ui->tabWidget->currentIndex());
}

void MainWindow::on_actionAT_T_syntax_x86_triggered(bool activated)
{
	std::string value = activated ? "att" : "intel";

	Preferences::instance().setValue("X86InstructionSyntax", value);

	if (m_data)
		refresh();
}

void MainWindow::on_addressHistoryListView_activated(const QModelIndex &index)
{
	int row = index.row();
	QModelIndex parent = index.parent();

	std::string s = m_addressHistoryViewModel->data(m_addressHistoryViewModel->index(row, 0, parent)).toString().toStdString();

	std::list<std::string> s_hist_entry = split_string(s, " ");
	std::string s_addr = s_hist_entry.front();

	if (!string_is_integer(s_addr, 16))
		return;

	uint64_t address = string_to_integer(s_addr);

	Model &model = Model::instance();

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
		symName = NameMangler::instance().mangle(p->getName());

	m_addressHistoryDisabled = true;
	updateSymbolView(address, symName);
	m_addressHistoryDisabled = false;
}

void MainWindow::on_editInstructionPushButton_clicked()
{
	m_editInstructionDialog->edit(m_currentInstruction);
}

void MainWindow::on_insnCurrentChanged(const QModelIndex& index, const QModelIndex& previous)
{
	int row = index.row();

	const IInstruction *cur = m_rowToInstruction[row];

	m_currentInstruction = cur;

	if (!cur)
		return;

	updateInstructionEncoding(cur);
	updateInfoBox(cur);
	updateDataView(cur->getAddress(), cur->getSize());

	ILineProvider::FileLine fileLine = Model::instance().getLineByAddress(cur->getAddress());

	if (!fileLine.m_isValid)
		return;

	if (m_sourceFileMap.find(fileLine.m_file) == m_sourceFileMap.end())
		m_sourceFileMap[fileLine.m_file] = UiHelpers::getFileContents(fileLine.m_file);
	const std::string &data = m_sourceFileMap[fileLine.m_file];

	// Update the source view if the current source file has changed
	if (m_currentSourceFile != fileLine.m_file) {
		m_currentSourceFile = fileLine.m_file;
		m_ui->sourceTextLabel->setText(QString(m_currentSourceFile.c_str()));
		m_ui->sourceTextEdit->setText(QString(data.c_str()));
	}

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
			if (m_addressToRow.find(target) != m_addressToRow.end())
				m_ui->instructionTableView->selectRow(m_addressToRow[target]);
		} else {
			updateSymbolView(target);
		}
	}
}

void MainWindow::on_instructionTableView_doubleClicked(const QModelIndex &index)
{
	on_instructionTableView_activated(index);
}

void MainWindow::on_locationLineEdit_returnPressed()
{
	QString text = m_ui->locationLineEdit->text();

	m_addressHistory.clear();
	m_addressHistoryViewModel->clear();

	Model::AddressList_t lst = Model::instance().lookupAddressesByText(text.toStdString());

	for (Model::AddressList_t::iterator it = lst.begin();
			it != lst.end();
			++it) {
		updateSymbolView(*it);
	}
}

void MainWindow::on_referencesTableView_activated(const QModelIndex &index)
{
	int row = index.row();
	QModelIndex parent = index.parent();

	std::string s = m_referencesViewModel->data(m_referencesViewModel->index(row, 0, parent)).toString().toStdString();
	std::string name = m_referencesViewModel->data(m_referencesViewModel->index(row, 1, parent)).toString().toStdString();

	if (!string_is_integer(s, 16))
		return;

	updateSymbolView(string_to_integer(s), name);
}

void MainWindow::on_sourceTextEdit_cursorPositionChanged()
{
	int cursorY = m_ui->sourceTextEdit->cursorRect().top();

	QScrollBar *vbar = m_ui->sourceTextEdit->verticalScrollBar();

	vbar->setValue(vbar->value() + cursorY - m_ui->sourceTextEdit->height() / 2);
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

		QString addr = QString::fromStdString(fmt("0x%llx", (unsigned long long)cur));
		if (syms.empty()) {
			QList<QStandardItem *> lst;

			lst.append(new QStandardItem(addr));
			m_referencesViewModel->appendRow(lst);
		} else {
			for (Model::SymbolList_t::const_iterator sIt = syms.begin();
					sIt != syms.end();
					++sIt) {
				ISymbol *sym = *sIt;
				QList<QStandardItem *> lst;

				// FIXME! Mr Gorbachev, mangle this name!
				QString name = QString::fromStdString(NameMangler::instance().mangle(sym->getName()));

				lst.append(new QStandardItem(addr));
				lst.append(new QStandardItem(name));

				m_referencesViewModel->appendRow(lst);
			}
		}
	}
}

void MainWindow::on_symbolTimerTriggered()
{
	Model::SymbolList_t syms;

	m_symbolMutex.lock();
	for (unsigned n = 0; n < 1000; n++) {
		if (m_currentSymbols.empty()) {
			m_timer->stop();
			break;
		}

		ISymbol *cur = m_currentSymbols.front();
		m_currentSymbols.pop_front();

		syms.push_back(cur);
	}
	m_symbolMutex.unlock();

	for (Model::SymbolList_t::iterator it = syms.begin();
			it != syms.end();
			++it) {
		handleSymbol(**it);
	}

	if (Model::instance().parsingComplete()) {
		restoreState();
	}
}

void MainWindow::onManglingChanged(bool enabled)
{
	m_ui->action_Mangle_names->setChecked(enabled);

	refresh();
}

void MainWindow::onPreferencesChanged(const std::string& key,
		const std::string& oldValue, const std::string& newValue)
{
	if (key == "X86InstructionSyntax") {
		m_ui->actionAT_T_syntax_x86->setChecked(newValue == "att");
	} else if (key == "QtMainWindowSize") {
		size_t comma = newValue.find(",");
		// Malformed, fix it
		if (comma == std::string::npos) {
			updatePreferences();
			return;
		}

		std::string w = newValue.substr(0, comma);
		std::string h = newValue.substr(comma + 1, newValue.size());

		if (string_to_integer(w) < 1024)
			w = "1024";
		if (string_to_integer(h) < 768)
			h = "768";

		setGeometry(geometry().left(), geometry().top(), string_to_integer(w), string_to_integer(h));
	}
}

void MainWindow::onSymbol(ISymbol& sym)
{
	m_symbolMutex.lock();
	m_currentSymbols.push_back(&sym);
	m_symbolMutex.unlock();
}

void MainWindow::refresh()
{
	delete m_referencesViewModel;
	delete m_symbolViewModel;

	m_addressToSymbolRowMap.clear();
	m_addressHistoryViewModel->clear();
	m_addressHistory.clear();

	setupSymbolView();
	setupReferencesView();

}

void MainWindow::restoreState()
{
	if (curSymName == "")
		return;

	// restore symbol
	Model &model = Model::instance();
	Model::AddressList_t lst = model.lookupAddressesByText(curSymName);

	for (Model::AddressList_t::iterator it = lst.begin();
		it != lst.end();
		++it) {
		updateSymbolView(*it);
	}

	// restore instruction
	if (curInsnOffset == 0) return;
	QModelIndex symIndex = m_ui->symbolTableView->currentIndex();
	int row = symIndex.row();
	QModelIndex parent = symIndex.parent();
	curSymAddr = m_symbolViewModel->data(m_symbolViewModel->index(row, 0, parent)).toString().toStdString();
	uint64_t curInsnAddr = curInsnOffset + string_to_integer(curSymAddr, 16);

	const ISymbol *sym = UiHelpers::getBestSymbol(string_to_integer(curSymAddr, 16), curSymName);

	if (!sym)
		return;

	if (sym->getType() == ISymbol::SYM_TEXT)
		updateInstructionView(curInsnAddr, *sym);
}

void MainWindow::saveState()
{
	// save the name of the current symbol
	QModelIndex symIndex = m_ui->symbolTableView->currentIndex();
	int row = symIndex.row();
	QModelIndex parent = symIndex.parent();
	curSymName = m_symbolViewModel->data(m_symbolViewModel->index(row, 7, parent)).toString().toStdString();
	// calculate curInsnOffset from symbol start (curInsnAddr - curSymAddr)
	curSymAddr = m_symbolViewModel->data(m_symbolViewModel->index(row, 0, parent)).toString().toStdString();
	QModelIndex insnIndex = m_ui->instructionTableView->currentIndex();
	row = insnIndex.row();
	parent = insnIndex.parent();
	std::string curInsnAddr = m_instructionViewModel->data(m_instructionViewModel->index(row, 0, parent)).toString().toStdString();
	curInsnOffset = string_to_integer(curInsnAddr, 16) - string_to_integer(curSymAddr, 16);
}

void MainWindow::setupAddressHistoryView()
{
	m_addressHistoryViewModel = new QStandardItemModel(0, 1, this);

	m_ui->addressHistoryListView->setModel(m_addressHistoryViewModel);
}

void MainWindow::setupDataView()
{
	m_dataViewStart = 0;
	m_dataViewEnd = 0;

	// We want the same font as for the instructions
	const QFont &font = m_ui->instructionTableView->font();
	QFontMetrics metrics = QFontMetrics(font);
	m_dataViewData = QHexEditData::fromMemory(QByteArray());

	m_dataViewHexEdit = new QHexEdit();
	m_dataViewHexEdit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
	m_dataViewHexEdit->setMinimumWidth(1024);
	m_dataViewHexEdit->setData(m_dataViewData);
	m_ui->gridLayoutHexView->addWidget(m_dataViewHexEdit);

	m_dataViewHexEdit->setFont(font);

	m_dataViewDataWriter = new QHexEditDataWriter(m_dataViewData);
}

void MainWindow::setupInfoBox()
{
}

void MainWindow::setupInstructionEncoding()
{
	QByteArray buf(32, 0x0);

	m_encodingData = QHexEditData::fromMemory(buf);

	// We want the same font as for the instructions
	const QFont &font = m_ui->instructionTableView->font();
	QFontMetrics metrics = QFontMetrics(font);

	m_ui->instructionEncodingLineEdit->setMinimumHeight(metrics.height() * 2); // Two rows

	m_encodingHexEdit = new QHexEdit(m_ui->instructionEncodingLineEdit);
	m_encodingHexEdit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
	m_encodingHexEdit->setMinimumWidth(1024); // Big enough, probably some better way
	m_encodingHexEdit->setData(m_encodingData);

	m_encodingHexEdit->setFont(font);
	m_encodingDataWriter = new QHexEditDataWriter(m_encodingData);
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

	connect(m_ui->instructionTableView->selectionModel(),
			SIGNAL(currentChanged(QModelIndex, QModelIndex)),
			this, SLOT(on_insnCurrentChanged(QModelIndex, QModelIndex)));

	setupInstructionLabels();
}

void MainWindow::setupReferencesView()
{
	m_referencesViewModel = new QStandardItemModel(0, 2, this);

	m_ui->referencesTableView->setModel(m_referencesViewModel);
	m_ui->instructionTableView->setColumnWidth(0, 80);
	m_ui->referencesTableView->horizontalHeader()->setStretchLastSection(true);
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
	m_ui->symbolTableView->setColumnWidth(0, 100);
	m_ui->symbolTableView->setColumnWidth(1, 80);
	m_ui->symbolTableView->setSelectionMode(QAbstractItemView::SingleSelection);

	// Start the symbol timer
	m_timer = new QTimer(this);
	connect(m_timer, SIGNAL(timeout()), SLOT(on_symbolTimerTriggered()));
	m_timer->start(100);
}



void MainWindow::updateSymbolView(uint64_t address, const std::string &name)
{
	const ISymbol *sym = UiHelpers::getBestSymbol(address, name);

	if (!sym)
		return;

	addHistoryEntry(address);
	std::string key = fmt("0x%llx_%s", (unsigned long long)sym->getAddress(), sym->getName().c_str());
	if (m_addressToSymbolRowMap.find(key) != m_addressToSymbolRowMap.end())
		m_ui->symbolTableView->selectRow(m_addressToSymbolRowMap[key]);

	// Scroll to the current index
	m_ui->symbolTableView->scrollTo(m_ui->symbolTableView->currentIndex());

	updateDataView(sym->getAddress(), sym->getSize());
	if (sym->getType() == ISymbol::SYM_TEXT)
		updateInstructionView(address, *sym);
}

void MainWindow::updateDataView(uint64_t address, size_t size)
{
	uint64_t markStart, markEnd;
	QColor color = QColor("green");
	emilpro::Model &model = emilpro::Model::instance();

	// Outside of the current section, lookup another
	if (address < m_dataViewStart ||
			address >= m_dataViewEnd) {
		const emilpro::ISymbol *section = model.getSection(address);

		if (!section)
			return;

		if (!section->getDataPtr())
			return;

		m_dataViewStart = section->getAddress();
		m_dataViewEnd = m_dataViewStart + section->getSize();

		QByteArray buf((char *)section->getDataPtr(), section->getSize());

		m_dataViewDataWriter->replace(0, buf);
		m_dataViewHexEdit->setBaseAddress(m_dataViewStart);
	}

	markStart = address - m_dataViewStart;
	markEnd = markStart + size - 1;

	m_dataViewHexEdit->clearHighlight();
	m_dataViewHexEdit->highlightBackground(markStart, markEnd, color);
	m_dataViewHexEdit->setCursorPos(markStart);
}

void MainWindow::updateHistoryEntry(const AddressHistory::Entry& e)
{
	if (!e.isValid())
		return;

	m_addressHistoryDisabled = true;
	updateSymbolView(e.getAddress());
	m_addressHistoryDisabled = false;

	// Highlight current item
	int historyIdx = m_addressHistory.currentIndex();
	auto idx = m_addressHistoryViewModel->index(historyIdx, 0);
	m_ui->addressHistoryListView->setCurrentIndex(idx);

}

void MainWindow::updateInfoBox(const emilpro::IInstruction* insn)
{
	if (!insn) {
		m_ui->instructionTextEdit->setText("No instruction");
		return;
	}

	QString s = QString::fromStdString(UiHelpers::getInstructionInfoString(*insn, true));

	m_ui->instructionTextEdit->setText(s);
}

void MainWindow::updateInstructionEncoding(const IInstruction* insn)
{
	emilpro::Model &model = emilpro::Model::instance();
	uint8_t buf[32];
	uint64_t address = insn->getAddress();
	uint64_t displayAddress = address & ~15;
	uint64_t returnedAddr;
	uint64_t markStart, markEnd;
	size_t sz;
	QColor color = QColor("green");

	if (!model.copyData(buf, displayAddress, 32, &returnedAddr, &sz))
		return;

	markStart = address - returnedAddr;
	markEnd = markStart + insn->getSize() - 1;

	m_encodingHexEdit->clearHighlight();
	m_encodingHexEdit->highlightBackground(markStart, markEnd, color);
	m_encodingHexEdit->setBaseAddress(returnedAddr);

	m_encodingDataWriter->replace(0, 32, QByteArray((const char *)buf, sizeof(buf)));
}

void MainWindow::updateInstructionView(uint64_t address, const ISymbol& sym)
{
	Model &model = Model::instance();
	InstructionList_t insns = model.getInstructions(sym.getAddress(), sym.getAddress() + sym.getSize());
	int row = 0;

	m_instructionViewModel->clear();
	setupInstructionLabels();

	m_addressToRow.clear();
	m_rowToInstruction.clear();
	m_forwardItemDelegate.update(insns, 60);
	m_backwardItemDelegate.update(insns, 60);

	for (InstructionList_t::iterator it = insns.begin();
			it != insns.end();
			++it, ++row) {
		IInstruction *cur = *it;

		m_rowToInstruction[row] = cur;
		m_addressToRow[cur->getAddress()] = row;

		QList<QStandardItem *> lst;

		QString addr = QString::fromStdString(fmt("0x%llx", (unsigned long long)cur->getAddress()));
		QString b = "";
		QString instruction = QString::fromStdString(cur->getString());
		QString f = "";
		QString target;

		const auto reloc = model.getRelocation(cur->getAddress(), cur->getSize());

		if (reloc) {
			target = QString::fromStdString(reloc->getTargetSymbol().getName() + " (reloc)");
		} else if (cur->getBranchTargetAddress() != IInstruction::INVALID_ADDRESS) {
			uint64_t targetAddress = cur->getBranchTargetAddress();
			Model::SymbolList_t targetSyms = model.getSymbolExact(targetAddress);

			if (targetSyms.empty() || (targetAddress >= sym.getAddress() && targetAddress < sym.getAddress() + sym.getSize())) {
				target = QString::fromStdString(fmt("0x%0llx", (long long)targetAddress));
			} else {
				const ISymbol *targetSym = targetSyms.front();

				target = QString::fromStdString(NameMangler::instance().mangle(targetSym->getName()));
			}
		}

		lst.append(new QStandardItem(addr));
		lst.append(new QStandardItem(b));
		lst.append(new QStandardItem(instruction));
		lst.append(new QStandardItem(f));
		lst.append(new QStandardItem(target));
		m_instructionViewModel->appendRow(lst);
	}

	m_ui->instructionTableView->resizeColumnsToContents();

	// Focus the current instruction
	if (m_addressToRow.find(address) != m_addressToRow.end())
		m_ui->instructionTableView->selectRow(m_addressToRow[address]);
}

void MainWindow::updatePreferences()
{
	Preferences::instance().setValue("QtMainWindowSize", fmt("%d,%d", width(), height()));
}
