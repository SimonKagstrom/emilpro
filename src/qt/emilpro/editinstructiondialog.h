#ifndef EDITINSTRUCTIONDIALOG_H
#define EDITINSTRUCTIONDIALOG_H

#include <QDialog>

#include <iinstruction.hh>

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

private:
    Ui::EditInstructionDialog *m_ui;
};

#endif // EDITINSTRUCTIONDIALOG_H
