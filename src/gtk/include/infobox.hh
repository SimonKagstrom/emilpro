#pragma once

#include <iinstruction.hh>
#include <preferences.hh>

#include <gtkmm.h>

class EditDialog;

class InfoBox : public emilpro::Preferences::IListener
{
public:
	InfoBox();

	void init(Glib::RefPtr<Gtk::Builder> builder);

	void onInstructionSelected(emilpro::IInstruction &insn);

private:
	void onEditButtonClicked();

	void onNetworkDialogOKClicked();

	virtual void onPreferencesChanged(const std::string &key,
			const std::string &oldValue, const std::string &newValue);

	Gtk::Label *m_label;
	Gtk::TextView *m_textView;
	EditDialog *m_dialog;
	Gtk::Dialog *m_networkDialog;

	Glib::RefPtr<Gtk::TextBuffer> m_textBuffer;
	Glib::RefPtr<Gtk::TextBuffer::TagTable> m_tagTable;

	bool m_networkDialogShown;
};
