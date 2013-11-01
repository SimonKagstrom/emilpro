#pragma once

#include <ilineprovider.hh>

#include <gtkmm.h>
#include <gtksourceviewmm.h>

#include <unordered_map>
#include <list>

class SourceView
{
public:
	SourceView();

	~SourceView();

	void init(Glib::RefPtr<Gtk::Builder> builder);

	void update(uint64_t address);

private:
	Glib::RefPtr<Gsv::Buffer> getSourceBuffer(emilpro::ILineProvider::FileLine &fileLine);
	typedef std::list<unsigned int> SourceLineNrList_t;

	typedef std::unordered_map<std::string, Glib::RefPtr<Gsv::Buffer>> FileToBufferMap_t;

	Gtk::ScrolledWindow *m_sourceScrolledWindow;
	FileToBufferMap_t m_filesToBuffer;
	Glib::RefPtr<Gsv::Buffer> m_emptyBuffer;
	Gsv::View *m_sourceView;
	Glib::RefPtr<Gsv::Buffer> m_currentBuffer;


	Glib::RefPtr<Gtk::TextBuffer::Tag> m_sourceTags[3];
	Glib::RefPtr<Gtk::TextBuffer::TagTable> m_tagTable;
	SourceLineNrList_t m_lastSourceLines;

	Gtk::Label *m_sourceFilename;

	Gdk::Color m_historyColors[3];
	Gdk::Color m_backgroundColor;
};
