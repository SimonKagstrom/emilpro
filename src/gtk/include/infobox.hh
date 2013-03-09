#pragma once

#include <iinstruction.hh>

#include <gtkmm.h>


class InfoBox
{
public:
	InfoBox();

	void init(Glib::RefPtr<Gtk::Builder> builder);

	void onInstructionSelected(emilpro::IInstruction &insn);

private:
	void onEditButtonClicked();

	Gtk::Label *m_label;
	Gtk::TextView *m_textView;
	Gtk::Button *m_editButton;
	Gtk::Dialog *m_dialog;

	Glib::RefPtr<Gtk::TextBuffer> m_textBuffer;
	Glib::RefPtr<Gtk::TextBuffer::TagTable> m_tagTable;
};
