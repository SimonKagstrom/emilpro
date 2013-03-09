#include <infobox.hh>
#include <instructionfactory.hh>
#include <utils.hh>

using namespace emilpro;

InfoBox::InfoBox()
{
}

void InfoBox::init(Glib::RefPtr<Gtk::Builder> builder)
{
	builder->get_widget("info_box_text_view", m_textView);
	panic_if(!m_textView,	"Can't get view");
	builder->get_widget("edit_instruction_model_button", m_editButton);
	panic_if(!m_editButton, "Can't get button");
	builder->get_widget("instruction_label", m_label);
	panic_if(!m_label, "Can't get label");
	builder->get_widget("edit_instruction_dialog", m_dialog);
	panic_if(!m_dialog, "Can't get dialog");

	m_tagTable = Gtk::TextBuffer::TagTable::create();
	m_textBuffer = Gtk::TextBuffer::create(m_tagTable);
	m_textView->set_buffer(m_textBuffer);

	m_editButton->signal_clicked().connect(sigc::mem_fun(*this,	&InfoBox::onEditButtonClicked));
}

void InfoBox::onInstructionSelected(IInstruction &insn)
{
	InstructionFactory::IInstructionModel *model = InstructionFactory::instance().getModelFromInstruction(insn);

	std::string s = "No instruction info, click edit to add";

	m_label->set_text(fmt("Instruction: %s",
			insn.getMnemonic().c_str()).c_str());

	if (model) {
		const char *type = "unknown";
		const char *privileged = "unknown";

		switch (model->getType())
		{
		case IInstruction::IT_CFLOW:
			type = "Control flow";
			break;
		case IInstruction::IT_DATA_HANDLING:
			type = "Data handling";
			break;
		case IInstruction::IT_ARITHMETIC_LOGIC:
			type = "Arithmetic/logic";
			break;
		case IInstruction::IT_OTHER:
			type = "Other";
			break;
		default:
			break;
		}

		Ternary_t isPrivileged = model->isPrivileged();

		if (isPrivileged == T_true)
			privileged = "yes";
		else if (isPrivileged == T_false)
			privileged = "no";

		s = fmt(
				"Type: %s\n"
				"Privileged: %s\n"
				"\n"
				"%s",
				type,
				privileged,
				model->getDescription().c_str()
				);
	}

	m_textBuffer->set_text(s);
}

void InfoBox::onEditButtonClicked()
{
	m_dialog->show();
}
