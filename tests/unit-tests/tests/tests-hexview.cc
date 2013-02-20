#include <gtkmm.h>

#include "../test.hh"

#include <utils.hh>
#include <hexview.hh>

TESTSUITE(hexview)
{
	uint8_t data[] =
	{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
	};

	TEST(endianness)
	{
		// We assume x86 for the unit tests.
		ASSERT_TRUE(cpu_is_little_endian());
	}

	TEST(test8)
	{
		HexView h;

		std::string s;

		s = h.getLine8(data);
		ASSERT_TRUE(s == "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff");
		s = h.getAscii(data);
		ASSERT_TRUE(s == "..\"3DUfw........");
	}

	TEST(test16)
	{
		HexView h;

		std::string s;

		s = h.getLine16((uint16_t *)data, false);
		ASSERT_TRUE(s == "0011 2233 4455 6677 8899 aabb ccdd eeff");

		s = h.getLine16((uint16_t *)data, true);
		ASSERT_TRUE(s == "1100 3322 5544 7766 9988 bbaa ddcc ffee");
	}

	TEST(test32)
	{
		HexView h;

		std::string s;

		s = h.getLine32((uint32_t *)data, false);
		ASSERT_TRUE(s == "00112233 44556677 8899aabb ccddeeff");

		s = h.getLine32((uint32_t *)data, true);
		ASSERT_TRUE(s == "33221100 77665544 bbaa9988 ffeeddcc");
	}

	TEST(test64)
	{
		HexView h;

		std::string s;

		s = h.getLine64((uint64_t *)data, true);
		ASSERT_TRUE(s == "7766554433221100 ffeeddccbbaa9988");

		s = h.getLine64((uint64_t *)data, false);
		ASSERT_TRUE(s == "0011223344556677 8899aabbccddeeff");
	}

	TEST(update)
	{
		HexView h;

		h.addData((void *)data, 0x1000, sizeof(data));

		std::string s8LE = h.handleAllData(8, true);

		ASSERT_TRUE(s8LE == "0x0000000000001000  00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff  ..\"3DUfw........\n");
		ASSERT_TRUE(h.m_addressToLineMap[0x1000] == 0ULL);
	}
}
