#ifndef EDITINSTRUCTIONDIALOG_H
#define EDITINSTRUCTIONDIALOG_H

#include <QDialog>

#include <iinstruction.hh>
#include <instructionfactory.hh>

namespace Ui {
class EditInstructionDialog;
}

class EditInstructionDialog : public QDialog
{
    Q_OBJECT

public:
    explicit EditInstructionDialog(QWidget *parent = 0);
    ~EditInstructionDialog();

    void edit(const emilpro::IInstruction *insn);

private slots:
    void on_buttonBox_accepted();

    void on_buttonBox_rejected();

private:
    Ui::EditInstructionDialog *m_ui;
    emilpro::InstructionFactory::IInstructionModel *m_currentModel;
    const emilpro::IInstruction *m_currentInstruction;
};

#endif // EDITINSTRUCTIONDIALOG_H
