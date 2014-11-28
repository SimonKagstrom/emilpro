#ifndef EDITINSTRUCTIONDIALOG_H
#define EDITINSTRUCTIONDIALOG_H

#include <QDialog>

#include <iinstruction.hh>
#include <instructionfactory.hh>
#include <architecturefactory.hh>

namespace Ui {
class EditInstructionDialog;
}

class EditInstructionDialog : public QDialog, public emilpro::ArchitectureFactory::IArchitectureListener
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
    void onArchitectureDetected(emilpro::ArchitectureFactory::Architecture_t arch,
                                emilpro::ArchitectureFactory::Machine_t mach);

    Ui::EditInstructionDialog *m_ui;
    emilpro::InstructionFactory::IInstructionModel *m_currentModel;
    const emilpro::IInstruction *m_currentInstruction;
    emilpro::ArchitectureFactory::Architecture_t m_currentArchitecture;
};

#endif // EDITINSTRUCTIONDIALOG_H
