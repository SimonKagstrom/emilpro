#pragma once

#include <iinstruction.hh>

#include <gtkmm.h>


class InfoBox
{
public:
	InfoBox();

	void init(Glib::RefPtr<Gtk::Label> label,
			Glib::RefPtr<Gtk::TextView> textView,
			Glib::RefPtr<Gtk::Button> button);

	void onInstructionSelected(emilpro::IInstruction &insn);

private:
	void onEditButtonClicked();

	Glib::RefPtr<Gtk::Label> m_label;
	Glib::RefPtr<Gtk::TextView> m_textView;
	Glib::RefPtr<Gtk::Button> m_editButton;
	Glib::RefPtr<Gtk::TextBuffer> m_textBuffer;
	Glib::RefPtr<Gtk::TextBuffer::TagTable> m_tagTable;
};
