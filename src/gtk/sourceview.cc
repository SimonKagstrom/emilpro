#include <sourceview.hh>
#include <model.hh>
#include <utils.hh>

using namespace emilpro;

SourceView::SourceView()
{
}

SourceView::~SourceView()
{
}

void SourceView::init(Glib::RefPtr<Gtk::Builder> builder)
{
	Gtk::FontButton *sourceFont;
	builder->get_widget("source_font", sourceFont);
	panic_if(!sourceFont,
			"Can't get source font");

	builder->get_widget("source_filename_label", m_sourceFilename);
	panic_if(!m_sourceFilename,
			"Can't get source label");

	builder->get_widget("source_view", m_sourceView);
	panic_if(!m_sourceView,
			"Can't get source view");
	m_sourceView->override_font(Pango::FontDescription(sourceFont->get_font_name()));

	m_tagTable = Gtk::TextBuffer::TagTable::create();
	for (unsigned i = 0; i < 3; i++) {
		Gtk::ColorButton *historyColor;
		builder->get_widget(fmt("history_color%d", i).c_str(), historyColor);
		panic_if(!historyColor,
				"Can't get history color");

		m_historyColors[i] = historyColor->get_color();

		m_sourceTags[i] = Gtk::TextBuffer::Tag::create();

		m_sourceTags[i]->property_paragraph_background_gdk() = m_historyColors[i];
		m_tagTable->add(m_sourceTags[i]);
	}

	m_emptyBuffer = Gsv::Buffer::create(m_tagTable);

	builder->get_widget("source_view_scrolled_window", m_sourceScrolledWindow);
}

void SourceView::update(uint64_t address)
{
	Model &model = Model::instance();

	ILineProvider::FileLine fileLine = model.getLineByAddress(address);

	Glib::RefPtr<Gsv::Buffer> buffer = getSourceBuffer(fileLine);

	if (m_currentBuffer != buffer) {
		m_sourceView->set_buffer(buffer);
		m_lastSourceLines.clear();
	}
	m_currentBuffer = buffer;

	m_sourceFilename->set_text(fileLine.m_file);

	// Should never happen, but anyway...
	if (!buffer)
		return;

	unsigned int line = fileLine.m_lineNr - 1;

	Gsv::Buffer::iterator it = buffer->get_iter_at_line(line);

	if (it == buffer->end())
		return;

	buffer->remove_all_tags(buffer->get_iter_at_line(0), buffer->get_iter_at_line(buffer->get_line_count()));

	m_lastSourceLines.push_back(line);
	if (m_lastSourceLines.size() > 3)
		m_lastSourceLines.pop_front();

	unsigned i = 0;
	for (SourceLineNrList_t::iterator lineIt = m_lastSourceLines.begin();
			lineIt != m_lastSourceLines.end();
			++lineIt, ++i) {
		unsigned int cur = *lineIt;

		Gsv::Buffer::iterator curIt = buffer->get_iter_at_line(cur);
		Gsv::Buffer::iterator itNext = buffer->get_iter_at_line(cur + 1);

		buffer->apply_tag(m_sourceTags[i], curIt, itNext);
	}

	Glib::RefPtr<Gtk::Adjustment> adj = m_sourceScrolledWindow->get_vadjustment();

	adj->set_value(adj->get_upper());

	it = buffer->get_iter_at_line(line - 5 < 0 ? 0 : line - 5);
	Glib::RefPtr<Gtk::TextBuffer::Mark> mark = buffer->create_mark(it);

	buffer->place_cursor(it);
	m_sourceView->scroll_to(mark);
	buffer->delete_mark(mark);
}

Glib::RefPtr<Gsv::Buffer> SourceView::getSourceBuffer(emilpro::ILineProvider::FileLine& fileLine)
{
	Glib::RefPtr<Gsv::Buffer> buffer;

	if (!fileLine.m_isValid)
		return m_emptyBuffer;

	if (m_filesToBuffer.find(fileLine.m_file) != m_filesToBuffer.end())
		return m_filesToBuffer[fileLine.m_file];

	size_t sz;
	char *p = (char *)read_file(&sz, "%s", fileLine.m_file.c_str());
	if (!p)
		return m_emptyBuffer;
	std::string data(p, sz);
	free(p);

	Glib::RefPtr<Gsv::LanguageManager> manager = Gsv::LanguageManager::get_default();
	Glib::RefPtr<Gsv::Language> language;

	bool uncertain;
	Glib::ustring content = Gio::content_type_guess(fileLine.m_file, data, uncertain);

	if (uncertain)
		content.clear();

	language = manager->guess_language(fileLine.m_file, content);
	if (!language)
		language = manager->get_language("cpp");

	buffer = Gsv::Buffer::create(m_tagTable);
	buffer->set_language(language);
	buffer->set_highlight_syntax(true);

	buffer->begin_not_undoable_action();
	buffer->set_text(data);
	buffer->end_not_undoable_action();

	m_filesToBuffer[fileLine.m_file] = buffer;

	return buffer;
}
