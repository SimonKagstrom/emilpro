#pragma once

#include <gtkmm.h>
#include <unordered_map>
#include <map>
#include <string>

// Unit test stuff
namespace hexview
{
	class test8;
	class test16;
	class test32;
	class test64;
	class update;
}

class HexView
{
public:
	friend class hexview::test8;
	friend class hexview::test16;
	friend class hexview::test32;
	friend class hexview::test64;
	friend class hexview::update;

	HexView();

	~HexView();

	void init();

	void clearData();

	void addData(void *data, uint64_t baseAddress, size_t size);

	void update();

	void setViewLittleEndian(bool littleEndian);

	bool getViewLittleEndian();

	void markRange(uint64_t address, size_t size);

	Gtk::TextView &getTextView(unsigned width);

private:
	class Data
	{
	public:
		Data() :
			m_base(0), m_p(0), m_size(0)
		{
		}

		Data(uint64_t base, void *ptr, size_t size) :
			m_base(base), m_p((uint8_t *)ptr), m_size(size)
		{
		}

		uint64_t m_base;
		uint8_t *m_p;
		size_t m_size;
	};

	typedef std::unordered_map<uint64_t, uint64_t> AddressToLineNr_t;
	typedef std::map<uint64_t, Data> DataMap_t;

	void markRangeInBuffer(uint64_t address, size_t size, Glib::RefPtr<Gtk::TextBuffer> buffer, unsigned viewIdx);

	std::string handleAllData(unsigned width, bool littleEndian, bool updateLineMap = false);

	std::string handleData(Data *p, unsigned width, bool littleEndian, bool updateLineMap = false);

	std::string getLine8(uint8_t *data);
	std::string getLine16(uint16_t *data, bool littleEndian);
	std::string getLine32(uint32_t *data, bool littleEndian);
	std::string getLine64(uint64_t *data, bool littleEndian);

	std::string getAscii(uint8_t *data);

	uint16_t sw16(uint16_t v, bool doSwap);
	uint32_t sw32(uint32_t v, bool doSwap);
	uint64_t sw64(uint64_t v, bool doSwap);

	Gtk::TextView *m_textViews[4];
	Glib::RefPtr<Gtk::TextBuffer> m_textBuffers[8];
	Glib::RefPtr<Gtk::TextBuffer::Tag> m_tag;
	Glib::RefPtr<Gtk::TextBuffer::TagTable> m_tagTable;

	AddressToLineNr_t m_addressToLineMap;
	DataMap_t m_data;

	bool m_viewIsLittleEndian;
	unsigned m_lineNr;
};
