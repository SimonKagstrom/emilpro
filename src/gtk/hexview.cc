#include <hexview.hh>
#include <ctype.h>
#include <utils.hh>
#include <model.hh>

HexView::HexView() :
	m_encodingView(NULL),
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

	m_data.m_valid = false;
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

std::string HexView::getLine8(const uint8_t* d)
{
	return fmt("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
			d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]);
}

std::string HexView::getLine16(const uint16_t* d, bool littleEndian)
{
	bool swp = !(cpu_is_little_endian() && littleEndian);

	return fmt("%04x %04x %04x %04x %04x %04x %04x %04x",
			sw16(d[0], swp), sw16(d[1], swp), sw16(d[2], swp),
			sw16(d[3], swp), sw16(d[4], swp), sw16(d[5], swp),
			sw16(d[6], swp), sw16(d[7], swp));
}

std::string HexView::getLine32(const uint32_t* d, bool littleEndian)
{
	bool swp = !(cpu_is_little_endian() && littleEndian);

	return fmt("%08x %08x %08x %08x",
			sw32(d[0], swp), sw32(d[1], swp), sw32(d[2], swp), sw32(d[3], swp));
}

std::string HexView::getLine64(const uint64_t* d, bool littleEndian)
{
	bool swp = !(cpu_is_little_endian() && littleEndian);

	return fmt("%016llx %016llx",
			(unsigned long long)sw64(d[0], swp), (unsigned long long)sw64(d[1], swp));
}

std::string HexView::getAscii(const uint8_t* data)
{
	char str[17];

	for (unsigned i = 0; i < 16; i++)
		str[i] = data[i] >= 0x20 && data[i] <= 0x7e ? data[i] : '.';
	str[16] = '\0';

	return std::string(str);
}

void HexView::init(Glib::RefPtr<Gtk::Builder> builder)
{
	m_tagTable = Gtk::TextBuffer::TagTable::create();
	m_tag = Gtk::TextBuffer::Tag::create();

	m_tagTable->add(m_tag);

	for (unsigned i = 0; i < 4; i++)
		m_textViews[i] = new Gtk::TextView();


	builder->get_widget("instruction_encoding_text_view", m_encodingView);
	panic_if(!m_encodingView,
			"Can't get encoding view");

	m_encodingBuffer = Gtk::TextBuffer::create(m_tagTable);
	m_encodingView->set_buffer(m_encodingBuffer);

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
	size_t strOff = 0;

	// Size for 8-bits
	std::string out(((p->m_size + 16) / 16) * 100,
			' ');

	for (off = 0; off < p->m_size; off += 16) {
		const uint8_t *curLine = p->m_p + off;
		size_t left = p->m_size - off;
		uint64_t curAddress = p->m_base + off;

		// Skip incomplete lines. Fix this in the future...
		if (left < 16)
			break;

		if (updateLineMap) {
			m_addressToLineMap[curAddress] = m_lineNr;

			m_lineNr++;
		}

		bool swp = !(cpu_is_little_endian() && littleEndian);
		char dst[256];
		char *p = dst;
		const uint8_t *d8 = curLine;
		uint16_t *d16 = (uint16_t *)curLine;
		uint32_t *d32 = (uint32_t *)curLine;
		uint64_t *d64 = (uint64_t *)curLine;

		p += sprintf(p, "0x%016llx  ", (unsigned long long)curAddress);

		switch (width)
		{
		case 8:
			p += sprintf(p, "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x  ",
					d8[0], d8[1], d8[2], d8[3], d8[4], d8[5], d8[6], d8[7], d8[8], d8[9], d8[10], d8[11], d8[12], d8[13], d8[14], d8[15]);
			break;
		case 16:
			p += sprintf(p, "%04x %04x %04x %04x %04x %04x %04x %04x          ",
					sw16(d16[0], swp), sw16(d16[1], swp), sw16(d16[2], swp),
					sw16(d16[3], swp), sw16(d16[4], swp), sw16(d16[5], swp),
					sw16(d16[6], swp), sw16(d16[7], swp));
			break;
		case 32:
			p += sprintf(p, "%08x %08x %08x %08x              ",
					sw32(d32[0], swp), sw32(d32[1], swp), sw32(d32[2], swp), sw32(d32[3], swp));
			break;
		case 64:
			p += sprintf(p, "%016llx %016llx                ",
			(unsigned long long)sw64(d64[0], swp), (unsigned long long)sw64(d64[1], swp));
			break;
		default:
			panic("Wrong width");
			break;
		}

		for (unsigned i = 0; i < 16; i++) {
			char cur = d8[i];

			*p = cur >= 0x20 && cur <= 0x7e ? cur : '.';
			p++;
		}
		*p++ = '\n';
		*p = '\0';

		out.replace(strOff, strlen(dst) + 1, dst); // Include the \0
		strOff += strlen(dst);
	}

	out.resize(strOff);

	return out;
}

std::string HexView::handleAllData(unsigned width, bool littleEndian, bool updateLineMap)
{
	return handleData(&m_data, width, littleEndian, updateLineMap);
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
	maybeUpdateData(address);

	if (!m_data.m_valid)
		return;

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
	unsigned width = 8;

	if (viewIdx == 1)
		width = 16;
	else if (viewIdx == 2)
		width = 32;
	else if (viewIdx == 3)
		width = 64;

	HexView::LineOffsetList_t regions = getMarkRegions(address, size, width);

	buffer->remove_all_tags(buffer->get_iter_at_line(0),
			buffer->get_iter_at_line(buffer->get_line_count()));

	unsigned firstLine = 0xffffffff;

	for (HexView::LineOffsetList_t::iterator it = regions.begin();
			it != regions.end();
			++it) {
		HexView::LineOffset *cur = &(*it);

		Gtk::TextBuffer::iterator lIt = buffer->get_iter_at_line(cur->m_line);
		if (lIt == buffer->end())
			continue;

		if (firstLine == 0xffffffff)
			firstLine = cur->m_line;

		Gtk::TextBuffer::iterator start = buffer->get_iter_at_offset(lIt.get_offset() + cur->m_offset);
		Gtk::TextBuffer::iterator end = buffer->get_iter_at_offset(lIt.get_offset() + cur->m_offset + cur->m_count);

		if (start == buffer->end())
			continue;

		buffer->apply_tag(m_tag, start, end);
	}

	Gtk::TextBuffer::iterator it = buffer->get_iter_at_line(firstLine < 5 ? 0 : firstLine - 5);
	Glib::RefPtr<Gtk::TextBuffer::Mark> mark = buffer->create_mark(it);

	m_textViews[viewIdx]->scroll_to(mark, 0.2);
	buffer->delete_mark(mark);

	m_textViews[viewIdx]->show_now();
}

void HexView::setMarkColor(Gdk::Color color)
{
	m_tag->property_background_gdk() = color;
}

HexView::LineOffsetList_t HexView::getMarkRegions(uint64_t address, size_t size, unsigned width)
{
	LineOffsetList_t out;

	if (size == 0)
		return out;

	size_t left = size;

	uint64_t curAddress = address;
	while (left > 0) {
		size_t onLine = left;

		if ((curAddress & 15) + onLine > 16)
			onLine = 16 - (curAddress & 15);

		if (onLine > left)
			onLine = left;

		AddressToLineNr_t::iterator aIt = m_addressToLineMap.find(curAddress & ~15);

		if (aIt == m_addressToLineMap.end())
			return out;

		LineOffsetList_t tmp = getMarkRegionsLine(aIt->second, curAddress, onLine, width);
		for (LineOffsetList_t::iterator it = tmp.begin();
				it != tmp.end();
				++it)
			out.push_back(*it);

		left -= onLine;
		if ((curAddress & 15) != 0)
			curAddress += 16 - (curAddress & 15);
		else
			curAddress += 16;
	}

	return out;
}

HexView::LineOffsetList_t HexView::getMarkRegionsLine(unsigned line, uint64_t address, size_t size,
		unsigned width)
{
	LineOffsetList_t out;

	uint32_t offset = address & 15;

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

	int delimiters = size / bytesPerDelimiter - 1;

	if (delimiters < 0)
		delimiters = 0;

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
		out = pV[7] | (pV[6] << 8ULL) | (pV[5] << 16ULL) | ((uint64_t)pV[4] << 24ULL) |
		((uint64_t)pV[3] << 32ULL) | ((uint64_t)pV[2] << 40ULL) | ((uint64_t)pV[1] << 48ULL) | ((uint64_t)pV[0] << 56ULL);

	return out;
}

void HexView::updateInstructionEncoding(uint64_t addrIn, size_t size)
{
	emilpro::Model &model = emilpro::Model::instance();
	uint64_t addr = addrIn & ~15;

	m_encodingBuffer->remove_all_tags(m_encodingBuffer->get_iter_at_line(0),
			m_encodingBuffer->get_iter_at_line(m_encodingBuffer->get_line_count()));

	const uint8_t *p = model.getData(addr, 16, NULL, NULL);
	if (!p) {
		m_encodingBuffer->set_text("No instruction");
		return;
	}

	std::string line = fmt("0x%016llx  %s  %s", (unsigned long long)addr, getLine8(p).c_str(), getAscii(p).c_str());

	HexView::LineOffsetList_t regions = getMarkRegionsLine(0, addrIn, size, 8);

	m_encodingBuffer->set_text(line);

	for (HexView::LineOffsetList_t::iterator it = regions.begin();
			it != regions.end();
			++it) {
		HexView::LineOffset *cur = &(*it);

		Gtk::TextBuffer::iterator lIt = m_encodingBuffer->get_iter_at_line(cur->m_line);
		if (lIt == m_encodingBuffer->end())
			continue;

		Gtk::TextBuffer::iterator start = m_encodingBuffer->get_iter_at_offset(lIt.get_offset() + cur->m_offset);
		Gtk::TextBuffer::iterator end = m_encodingBuffer->get_iter_at_offset(lIt.get_offset() + cur->m_offset + cur->m_count);

		if (start == m_encodingBuffer->end())
			continue;

		m_encodingBuffer->apply_tag(m_tag, start, end);
	}
}

Gtk::TextView& HexView::getEncodingTextView()
{
	return *m_encodingView;
}

void HexView::updateData(uint64_t address)
{
	emilpro::Model &model = emilpro::Model::instance();

	m_data.m_valid = false;

	uint64_t start, end;
	const uint8_t *p = model.getSurroundingData(address, 4096, &start, &end);

	if (!p)
		return;

	m_data = Data(start, p, end - start);

	computeBuffers();
}

void HexView::maybeUpdateData(uint64_t address)
{
	// Even out address to 16 bytes
	address = address & ~15;

	if (!m_data.m_valid) {
		updateData(address);

		return;
	}

	int64_t diffStart = address - m_data.m_base;
	int64_t diffEnd = address - (m_data.m_base + m_data.m_size);

	if (diffStart < 256 ||
			diffEnd > -256)
		updateData(address);
}

void HexView::computeBuffers()
{
	m_lineNr = 0;

	std::string s8LE = handleAllData(8, true, true);
	m_textBuffers[0]->set_text(s8LE);
	m_textBuffers[4]->set_text(s8LE); // The same

	std::string s16LE = handleAllData(16, true);
	m_textBuffers[1]->set_text(s16LE);

	std::string s32LE = handleAllData(32, true);
	m_textBuffers[2]->set_text(s32LE);

	std::string s64LE = handleAllData(64, true);
	m_textBuffers[3]->set_text(s64LE);


	std::string s16BE = handleAllData(16, false);
	m_textBuffers[5]->set_text(s16BE);

	std::string s32BE = handleAllData(32, false);
	m_textBuffers[6]->set_text(s32BE);

	std::string s64BE = handleAllData(64, false);
	m_textBuffers[7]->set_text(s64BE);

	// Setup the view
	setViewLittleEndian(m_viewIsLittleEndian);
}
