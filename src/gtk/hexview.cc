#include <hexview.hh>
#include <ctype.h>
#include <utils.hh>

HexView::HexView() :
	m_viewIsLittleEndian(cpu_is_little_endian()),
	m_lineNr(0)
{
}

HexView::~HexView()
{
}

void HexView::clearData()
{
	for (unsigned i = 0; i < 8; i++)
		m_textBuffers[i] = Gtk::TextBuffer::create(m_tagTable);
	for (unsigned i = 0; i < 4; i++)
		m_textViews[i]->set_buffer(m_textBuffers[i]);

	m_data.clear();
}

void HexView::addData(void* data, uint64_t baseAddress, size_t size)
{
	m_data[baseAddress] = Data(baseAddress, data, size);
}

void HexView::update()
{
	m_lineNr = 0;

	std::string s8LE = handleAllData(8, true, true);
	std::string s16LE = handleAllData(16, true);
	std::string s32LE = handleAllData(32, true);
	std::string s64LE = handleAllData(64, true);

	std::string s8BE = handleAllData(8, false);
	std::string s16BE = handleAllData(16, false);
	std::string s32BE = handleAllData(32, false);
	std::string s64BE = handleAllData(64, false);

	m_textBuffers[0]->set_text(s8LE);
	m_textBuffers[1]->set_text(s16LE);
	m_textBuffers[2]->set_text(s32LE);
	m_textBuffers[3]->set_text(s64LE);

	m_textBuffers[4]->set_text(s8BE);
	m_textBuffers[5]->set_text(s16BE);
	m_textBuffers[6]->set_text(s32BE);
	m_textBuffers[7]->set_text(s64BE);

	unsigned viewOff = m_viewIsLittleEndian ? 0 : 4;

	for (unsigned i = 0; i < 4; i++)
		m_textViews[i]->set_buffer(m_textBuffers[viewOff + i]);
}

Gtk::TextView &HexView::getTextView(unsigned width)
{
	switch (width)
	{
	case 8:
		return *m_textViews[0];
	case 16:
		return *m_textViews[1];
	case 32:
		return *m_textViews[2];
	case 64:
		return *m_textViews[3];
	default:
		panic("Invalid argument: %u", width);
		break;
	}

	return *m_textViews[0];
}

std::string HexView::getLine8(uint8_t* d)
{
	return fmt("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
			d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]);
}

std::string HexView::getLine16(uint16_t* d, bool littleEndian)
{
	bool swp = !(cpu_is_little_endian() && littleEndian);

	return fmt("%04x %04x %04x %04x %04x %04x %04x %04x",
			sw16(d[0], swp), sw16(d[1], swp), sw16(d[2], swp),
			sw16(d[3], swp), sw16(d[4], swp), sw16(d[5], swp),
			sw16(d[6], swp), sw16(d[7], swp));
}

std::string HexView::getLine32(uint32_t* d, bool littleEndian)
{
	bool swp = !(cpu_is_little_endian() && littleEndian);

	return fmt("%08x %08x %08x %08x",
			sw32(d[0], swp), sw32(d[1], swp), sw32(d[2], swp), sw32(d[3], swp));
}

std::string HexView::getLine64(uint64_t* d, bool littleEndian)
{
	bool swp = !(cpu_is_little_endian() && littleEndian);

	return fmt("%016llx %016llx",
			sw64(d[0], swp), sw64(d[1], swp));
}

std::string HexView::getAscii(uint8_t* data)
{
	char str[17];

	for (unsigned i = 0; i < 16; i++)
		str[i] = isprint(data[i]) ? data[i] : '.';
	str[16] = '\0';

	return std::string(str);
}

void HexView::init()
{
	m_tagTable = Gtk::TextBuffer::TagTable::create();
	m_tag = Gtk::TextBuffer::Tag::create();

	m_tagTable->add(m_tag);

	for (unsigned i = 0; i < 4; i++)
		m_textViews[i] = new Gtk::TextView();

	clearData();
}

uint16_t HexView::sw16(uint16_t v, bool doSwap)
{
	uint16_t out = v;
	uint8_t *pV = (uint8_t *)&v;

	if (doSwap)
		out = pV[1] | (pV[0] << 8);

	return out;
}

uint32_t HexView::sw32(uint32_t v, bool doSwap)
{
	uint32_t out = v;
	uint8_t *pV = (uint8_t *)&v;

	if (doSwap)
		out = pV[3] | (pV[2] << 8) | (pV[1] << 16) | (pV[0] << 24);

	return out;
}

std::string HexView::handleData(Data* p, unsigned width, bool littleEndian, bool updateLineMap)
{
	size_t off;

	std::string out;

	for (off = 0; off < p->m_size; off += 16) {
		uint8_t *curLine = p->m_p + off;
		size_t left = p->m_size - off;
		uint64_t curAddress = p->m_base + off;

		// Skip incomplete lines. Fix this in the future...
		if (left < 16)
			break;

		if (updateLineMap) {
			m_addressToLineMap[curAddress] = m_lineNr;

			m_lineNr++;
		}

		std::string hex;

		switch (width)
		{
		case 8:
			hex = getLine8(curLine);
			break;
		case 16:
			hex = getLine16((uint16_t *)curLine, littleEndian);
			break;
		case 32:
			hex = getLine32((uint32_t *)curLine, littleEndian);
			break;
		case 64:
			hex = getLine64((uint64_t *)curLine, littleEndian);
			break;
		default:
			panic("Wrong width");
			break;
		}

		std::string ascii = getAscii(curLine);

		out  =  out + fmt("0x%016llx  %-47s  %s\n", curAddress, hex.c_str(), ascii.c_str());
	}

	return out;
}

std::string HexView::handleAllData(unsigned width, bool littleEndian, bool updateLineMap)
{
	unsigned n = 0;
	std::string out;

	for (DataMap_t::iterator it = m_data.begin();
			it != m_data.end();
			++it, ++n) {
		Data *cur = &it->second;

		out = out + handleData(cur, width, littleEndian, updateLineMap);
		if (n < m_data.size() - 1) {
			out = out + "...\n";
			m_lineNr++;
		}
	}

	return out;
}

void HexView::setViewLittleEndian(bool littleEndian)
{
	if (m_viewIsLittleEndian != littleEndian) {
		unsigned viewOff = littleEndian ? 0 : 4;

		for (unsigned i = 0; i < 4; i++)
			m_textViews[i]->set_buffer(m_textBuffers[viewOff + i]);
	}
	m_viewIsLittleEndian = littleEndian;
}

bool HexView::getViewLittleEndian()
{
	return m_viewIsLittleEndian;
}

void HexView::markRange(uint64_t address, size_t size)
{
	AddressToLineNr_t::iterator aIt = m_addressToLineMap.find(address & ~15);

	if (aIt == m_addressToLineMap.end())
		return;

	for (unsigned int i = 0; i < 4; i++) {
		markRangeInBuffer(address, size, m_textBuffers[i], i);
	}
}

void HexView::markRangeInBuffer(uint64_t address, size_t size,
		Glib::RefPtr<Gtk::TextBuffer> buffer, unsigned viewIdx)
{
	unsigned line = m_addressToLineMap[address & ~15];

	Gtk::TextBuffer::iterator it = buffer->get_iter_at_line(line);
	Gtk::TextBuffer::iterator itNext = buffer->get_iter_at_line(line + 1);

	buffer->remove_all_tags(buffer->get_iter_at_line(0), buffer->get_iter_at_line(buffer->get_line_count()));

	if (it == buffer->end() || itNext == buffer->end())
		return;

	buffer->apply_tag(m_tag, it, itNext);

	it = buffer->get_iter_at_line(line < 5 ? 0 : line - 5);
	Glib::RefPtr<Gtk::TextBuffer::Mark> mark = buffer->create_mark(it);

	m_textViews[viewIdx]->scroll_to(mark, 0.2);
	buffer->delete_mark(mark);
}

void HexView::setMarkColor(Gdk::Color color)
{
	m_tag->property_paragraph_background_gdk() = color;
}

HexView::LineOffsetList_t HexView::getMarkRegions(uint64_t address, size_t size, unsigned width)
{
	LineOffsetList_t out;

	if (size == 0)
		return out;

	AddressToLineNr_t::iterator aIt = m_addressToLineMap.find(address & ~15);

	if (aIt == m_addressToLineMap.end())
		return out;

	uint32_t offset = address & 15;

	unsigned line = aIt->second;

	const unsigned startOfData = 20;
	const unsigned startOfAscii = 69;

	unsigned bytesPerDelimiter = 1; // assume 8-bits

	switch (width)
	{
	case 16:
		bytesPerDelimiter = 2;
		break;
	case 32:
		bytesPerDelimiter = 4;
		break;
	case 64:
		bytesPerDelimiter = 8;
		break;
	default:
		break;
	}

	unsigned delimiters = size / bytesPerDelimiter - 1;

	if (address % bytesPerDelimiter == 0 && size <= bytesPerDelimiter)
		delimiters = 0;

	unsigned startOffset = startOfData + 2 * offset + offset / bytesPerDelimiter;
	unsigned len = size * 2 + delimiters;

	out.push_back(LineOffset(line, startOffset, len));

	// Ascii stuff
	startOffset = startOfAscii + offset;
	len = size;

	out.push_back(LineOffset(line, startOffset, len));

	return out;
}

uint64_t HexView::sw64(uint64_t v, bool doSwap)
{
	uint64_t out = v;
	uint8_t *pV = (uint8_t *)&v;

	if (doSwap)
		out = pV[7] | (pV[6] << 8ULL) | (pV[5] << 16ULL) | (pV[4] << 24ULL) |
		((uint64_t)pV[3] << 32ULL) | ((uint64_t)pV[2] << 40ULL) | ((uint64_t)pV[1] << 48ULL) | ((uint64_t)pV[0] << 56ULL);

	return out;
}






