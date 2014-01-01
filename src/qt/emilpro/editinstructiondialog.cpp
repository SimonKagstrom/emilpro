#include "editinstructiondialog.h"
#include "ui_editinstructiondialog.h"

#include <instructionfactory.hh>

using namespace emilpro;

EditInstructionDialog::EditInstructionDialog(QWidget *parent) :
    QDialog(parent),
    m_ui(new Ui::EditInstructionDialog)
{
    m_ui->setupUi(this);
}

EditInstructionDialog::~EditInstructionDialog()
{
    delete m_ui;
}

void EditInstructionDialog::edit(const IInstruction* insn)
{
	if (!insn)
		return;

	m_ui->instructionDescriptionTextEdit->clear();
	InstructionFactory::IInstructionModel *insnModel = InstructionFactory::instance().getModelFromInstruction(*insn);

	if (insnModel) {
		m_ui->instructionDescriptionTextEdit->setText(QString::fromStdString(insnModel->getDescription()));
	}

	show();
}
