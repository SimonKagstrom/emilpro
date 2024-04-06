#include <infobox.hh>
#include <instructionfactory.hh>
#include <configuration.hh>
#include <server.hh>
#include <preferences.hh>
#include <utils.hh>
#include <ui-helpers.hh>

#include <sys/stat.h>
#include <sys/types.h>

using namespace emilpro;

class EditDialog : public ArchitectureFactory::IArchitectureListener
{
public:
	EditDialog() :
		m_dialog(NULL),
		m_currentInstruction(NULL),
		m_currentArchitecture(bfd_arch_unknown)
	{
	}

	void init(Glib::RefPtr<Gtk::Builder> builder)
	{
		ArchitectureFactory::instance().registerListener(this);

		builder->get_widget("edit_instruction_dialog", m_dialog);
		panic_if(!m_dialog, "Can't get dialog");

		builder->get_widget("edit_instruction_type_combobox", m_typeComboBox);
		panic_if(!m_typeComboBox, "Can't get combobox");
		builder->get_widget("edit_instruction_privileged_combobox", m_privilegedComboBox);
		panic_if(!m_privilegedComboBox, "Can't get combobox");
		builder->get_widget("edit_instruction_description_textview", m_textView);
		panic_if(!m_textView, "Can't get textview");

		builder->get_widget("instruction_dialog_cancel_button", m_cancelButton);
		panic_if(!m_cancelButton, "Can't get button");
		builder->get_widget("instruction_dialog_ok_button", m_okButton);
		panic_if(!m_okButton, "Can't get button");

		m_tagTable = Gtk::TextBuffer::TagTable::create();
		m_textBuffer = Gtk::TextBuffer::create(m_tagTable);
		m_textView->set_buffer(m_textBuffer);
		m_textView->set_wrap_mode(Gtk::WRAP_WORD);

		m_okButton->signal_clicked().connect(sigc::mem_fun(*this,
				&EditDialog::onOkClicked));
		m_cancelButton->signal_clicked().connect(sigc::mem_fun(*this,
				&EditDialog::onCancelClicked));
	}

	void show()
	{
		if (!m_currentInstruction)
			return;

		InstructionFactory::IInstructionModel *model = InstructionFactory::instance().getModelFromInstruction(*m_currentInstruction);

		if (model) {
			m_typeComboBox->set_active(typeToIndex(model->getType()));
			m_privilegedComboBox->set_active(ternaryToIndex(model->isPrivileged()));
			m_textBuffer->set_text(model->getDescription());
		} else {
			m_typeComboBox->set_active(0);
			m_privilegedComboBox->set_active(2);
			m_textBuffer->set_text("");
		}

		m_dialog->set_title(fmt("Editing instruction '%s'",
				m_currentInstruction->getMnemonic().c_str()));

		m_dialog->show();
	}

	void setCurrentInstruction(IInstruction &insn)
	{
		m_currentInstruction = &insn;
	}

private:
	class EditDialogModelColumns : public Gtk::TreeModelColumnRecord
	{
	public:
		EditDialogModelColumns()
		{
			add(m_name);
		}

		Gtk::TreeModelColumn<Glib::ustring> m_name;
	};

	void onArchitectureDetected(ArchitectureFactory::Architecture_t arch,
			ArchitectureFactory::Machine_t mach)
	{
		m_currentArchitecture = arch;
	}

	int typeToIndex(IInstruction::InstructionType_t type)
	{
		return (int)type;
	}

	IInstruction::InstructionType_t indexToType(int idx)
	{
		return (IInstruction::InstructionType_t)idx;
	}

	int ternaryToIndex(Ternary_t ternary)
	{
		return (int)ternary;
	}

	Ternary_t indexToTernary(int idx)
	{
		return (Ternary_t)idx;
	}

	void onCancelClicked()
	{
		m_dialog->hide();
	}

	void onOkClicked()
	{
		if (!m_currentInstruction)
			return;

		Configuration &conf = Configuration::instance();

		InstructionFactory::IInstructionModel *model = InstructionFactory::instance().getModelFromInstruction(*m_currentInstruction);

		if (!model)
			model = InstructionFactory::instance().createModelForInstruction(*m_currentInstruction);

		std::string descr(m_textBuffer->get_text());

		model->setDescription(descr);
		model->setType(indexToType(m_typeComboBox->get_active_row_number()));
		model->setPrivileged(indexToTernary(m_privilegedComboBox->get_active_row_number()));
		model->setTimeStamp(get_utc_timestamp());

		std::string archStr = ArchitectureFactory::instance().getNameFromArchitecture(m_currentArchitecture);

		// Create architecture dir
		std::string archDir = fmt("%s/%s",
				conf.getPath(Configuration::DIR_LOCAL).c_str(),
				archStr.c_str());
		::mkdir(archDir.c_str(), 0744);

		std::string fileName = fmt("%s/%s.xml",
				archDir.c_str(),
				m_currentInstruction->getMnemonic().c_str());

		std::string xml = model->toXml();

		write_file((void *)xml.c_str(), xml.size(),
				"%s", fileName.c_str());
		Server::instance().sendAndReceive();

		m_dialog->hide();
	}

	Gtk::Dialog *m_dialog;
	IInstruction *m_currentInstruction;
	ArchitectureFactory::Architecture_t m_currentArchitecture;

	Gtk::ListStore *m_typeListStore;
	Gtk::ListStore *m_privilegedListStore;
	EditDialogModelColumns m_typeColumns;
	EditDialogModelColumns m_privilegedColumns;

	Gtk::ComboBox *m_typeComboBox;
	Gtk::ComboBox *m_privilegedComboBox;

	Gtk::Button *m_cancelButton;
	Gtk::Button *m_okButton;

	Gtk::TextView *m_textView;

	Glib::RefPtr<Gtk::TextBuffer> m_textBuffer;
	Glib::RefPtr<Gtk::TextBuffer::TagTable> m_tagTable;

};

InfoBox::InfoBox() :
		m_networkDialogShown(false)
{
	m_dialog = new EditDialog();

	Preferences::instance().registerListener("NetworkDialogWarningShown", this);
}

void InfoBox::init(Glib::RefPtr<Gtk::Builder> builder)
{
	Gtk::Button *editButton;
	Gtk::Button *networkDialogOKButton;

	m_dialog->init(builder);

	builder->get_widget("info_box_text_view", m_textView);
	panic_if(!m_textView,	"Can't get view");
	builder->get_widget("edit_instruction_model_button", editButton);
	panic_if(!editButton, "Can't get button");
	builder->get_widget("instruction_label", m_label);
	panic_if(!m_label, "Can't get label");
	builder->get_widget("network_warning_dialog", m_networkDialog);
	panic_if(!m_networkDialog,	"Can't get network dialog");
	builder->get_widget("network_dialog_ok_button", networkDialogOKButton);
	panic_if(!networkDialogOKButton, "Can't get button");

	m_tagTable = Gtk::TextBuffer::TagTable::create();
	m_textBuffer = Gtk::TextBuffer::create(m_tagTable);
	m_textView->set_buffer(m_textBuffer);
	m_textView->set_wrap_mode(Gtk::WRAP_WORD);

	editButton->signal_clicked().connect(sigc::mem_fun(*this, &InfoBox::onEditButtonClicked));
	networkDialogOKButton->signal_clicked().connect(sigc::mem_fun(*this, &InfoBox::onNetworkDialogOKClicked));
}

void InfoBox::onInstructionSelected(IInstruction &insn)
{
	m_dialog->setCurrentInstruction(insn);

	std::string s = UiHelpers::getInstructionInfoString(insn);

	m_label->set_text(fmt("Instruction: %s",
			insn.getMnemonic().c_str()).c_str());

	m_textBuffer->set_text(s);
}

void InfoBox::onEditButtonClicked()
{
	m_dialog->show();

	if (!m_networkDialogShown) {
		m_networkDialog->show();
		Preferences::instance().setValue("NetworkDialogWarningShown", "yes");
	}
}

void InfoBox::onNetworkDialogOKClicked()
{
	m_networkDialog->hide();
}

void InfoBox::onPreferencesChanged(const std::string &key,
			const std::string &oldValue, const std::string &newValue)
{
	if (key != "NetworkDialogWarningShown")
		return;

	if (newValue == "yes")
		m_networkDialogShown = true;
	else
		m_networkDialogShown = false;
}
