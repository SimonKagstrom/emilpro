#pragma once

#include <gtkmm.h>

#include <unordered_map>
#include <map>
#include <string>
#include <list>
#include <thread>

// Unit test stuff
namespace hexview
{
	class test8;
	class test16;
	class test32;
	class test64;
	class update;
	class mark;
	class markSelfTest;
	class MarkFixture;
	class maybeUpdateData;
}

class HexView
{
public:
	friend class hexview::test8;
	friend class hexview::test16;
	friend class hexview::test32;
	friend class hexview::test64;
	friend class hexview::update;
	friend class hexview::mark;
	friend class hexview::markSelfTest;
	friend class hexview::MarkFixture;
	friend class hexview::maybeUpdateData;

	HexView();

	~HexView();

	void init(Glib::RefPtr<Gtk::Builder> builder);

	void clearData();

	void setMarkColor(Gdk::Color color);

	void setViewLittleEndian(bool littleEndian);

	bool getViewLittleEndian();

	void markRange(uint64_t address, size_t size);

	Gtk::TextView &getTextView(unsigned width);

	Gtk::TextView &getEncodingTextView();


	void updateInstructionEncoding(uint64_t offset, size_t size);

protected:
	// Just for the unit test, ignore this otherwise
	virtual void updateData(uint64_t address);

private:
	class Data
	{
	public:
		Data() :
			m_base(0), m_p(0), m_size(0), m_valid(false)
		{
		}

		Data(uint64_t base, const uint8_t *ptr, size_t size) :
			m_base(base), m_p(ptr), m_size(size), m_valid(true)
		{
		}

		uint64_t m_base;
		const uint8_t *m_p;
		size_t m_size;
		bool m_valid;
	};

	class LineOffset
	{
	public:
		LineOffset() :
			m_line(0), m_offset(0), m_count(0)
		{
		}

		LineOffset(unsigned line, unsigned offset, unsigned count) :
			m_line(line), m_offset(offset), m_count(count)
		{
		}

		unsigned m_line;
		unsigned m_offset;
		unsigned m_count;
	};

	typedef std::unordered_map<uint64_t, uint64_t> AddressToLineNr_t;
	typedef std::map<uint64_t, Data> DataMap_t;
	typedef std::list<LineOffset> LineOffsetList_t;

	void maybeUpdateData(uint64_t address);

	void markRangeInBuffer(uint64_t address, size_t size, Glib::RefPtr<Gtk::TextBuffer> buffer, unsigned viewIdx);

	LineOffsetList_t getMarkRegions(uint64_t address, size_t size, unsigned width);

	LineOffsetList_t getMarkRegionsLine(unsigned line, uint64_t address, size_t size, unsigned width);

	std::string handleAllData(unsigned width, bool littleEndian, bool updateLineMap = false);

	std::string handleData(Data *p, unsigned width, bool littleEndian, bool updateLineMap = false);

	std::string getLine8(const uint8_t *data);
	std::string getLine16(const uint16_t *data, bool littleEndian);
	std::string getLine32(const uint32_t *data, bool littleEndian);
	std::string getLine64(const uint64_t *data, bool littleEndian);

	std::string getAscii(const uint8_t *data);

	uint16_t sw16(uint16_t v, bool doSwap);
	uint32_t sw32(uint32_t v, bool doSwap);
	uint64_t sw64(uint64_t v, bool doSwap);
	void computeBuffers();

	Gtk::TextView *m_textViews[4];
	Glib::RefPtr<Gtk::TextBuffer> m_textBuffers[8];
	Glib::RefPtr<Gtk::TextBuffer::Tag> m_tag;
	Glib::RefPtr<Gtk::TextBuffer::TagTable> m_tagTable;

	Gtk::TextView* m_encodingView;
	Glib::RefPtr<Gtk::TextBuffer> m_encodingBuffer;

	AddressToLineNr_t m_addressToLineMap;
	Data m_data;

	bool m_viewIsLittleEndian;
	unsigned m_lineNr;
};
