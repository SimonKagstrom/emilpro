#include "editinstructiondialog.h"
#include "ui_editinstructiondialog.h"

#include <instructionfactory.hh>
#include <utils.hh>

using namespace emilpro;

EditInstructionDialog::EditInstructionDialog(QWidget *parent) :
    QDialog(parent),
    m_ui(new Ui::EditInstructionDialog),
    m_currentModel(NULL),
    m_currentInstruction(NULL)
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

	m_ui->instructionPrivilegedComboBox->setCurrentIndex(0);
	m_ui->instructionTypeComboBox->setCurrentIndex(0);
	m_ui->instructionDescriptionTextEdit->clear();

	m_currentModel = InstructionFactory::instance().getModelFromInstruction(*insn);
	m_currentInstruction = insn;

	if (m_currentModel) {
		IInstruction::InstructionType_t type = m_currentModel->getType();
		Ternary_t privileged = m_currentModel->isPrivileged();
		int typeIdx = 0; // Unknown
		int privilegedIdx = 0; // Unknown


		if (privileged == T_true)
			privilegedIdx = 1;
		else if (privileged == T_false)
			privilegedIdx = 2;

		switch (type)
		{
		default:
		case IInstruction::IT_UNKNOWN:
			break;
		case IInstruction::IT_DATA_HANDLING:
			typeIdx = 1; break;
		case IInstruction::IT_CFLOW:
			typeIdx = 2; break;
		case IInstruction::IT_CALL:
			typeIdx = 3; break;
		case IInstruction::IT_ARITHMETIC_LOGIC:
			typeIdx = 4; break;
		case IInstruction::IT_OTHER:
			typeIdx = 5; break;
		}

		m_ui->instructionDescriptionTextEdit->setText(QString::fromStdString(m_currentModel->getDescription()));
		m_ui->instructionPrivilegedComboBox->setCurrentIndex(privilegedIdx);
		m_ui->instructionTypeComboBox->setCurrentIndex(typeIdx);
	}

	show();
}

void EditInstructionDialog::on_buttonBox_accepted()
{
	int privilegedIdx = m_ui->instructionPrivilegedComboBox->currentIndex();
	int typeIdx = m_ui->instructionTypeComboBox->currentIndex();
	QString descriptionStr = m_ui->instructionDescriptionTextEdit->toPlainText();

	if (!m_currentModel)
		m_currentModel = InstructionFactory::instance().createModelForInstruction(*m_currentInstruction);

	IInstruction::InstructionType_t type = IInstruction::IT_UNKNOWN;
	Ternary_t privileged = T_unknown;

	switch (typeIdx)
	{
	default:
	case 0:
		type = IInstruction::IT_UNKNOWN; break;
	case 1:
		type = IInstruction::IT_DATA_HANDLING; break;
	case 2:
		type = IInstruction::IT_CFLOW; break;
	case 3:
		type = IInstruction::IT_CALL; break;
	case 4:
		type = IInstruction::IT_ARITHMETIC_LOGIC; break;
	case 5:
		type = IInstruction::IT_OTHER; break;
	}

	switch (privilegedIdx)
	{
	default:
	case 0:
		privileged = T_unknown; break;
	case 1:
		privileged = T_true; break;
	case 2:
		privileged = T_false; break;
	}

	m_currentModel->setType(type);
	m_currentModel->setPrivileged(privileged);
	m_currentModel->setDescription(descriptionStr.toStdString());

#warning Actually save the model
}

void EditInstructionDialog::on_buttonBox_rejected()
{
}
