#include <gtkmm.h>

#include "../test.hh"

#include <utils.hh>
#include <hexview.hh>

#include <ctype.h>

TESTSUITE(hexview)
{
	class MarkFixture
	{
	public:
		MarkFixture()
		{
		}

		bool getStartAndSize(const std::string &mask, uint64_t &startAddress, size_t &size)
		{
			unsigned zeros = 0;
			unsigned crosses = 0;

			printf("%s", mask.c_str());

			// Find first cross
			for (unsigned i = 20; i < 20+49; i++) {
				if (mask[i] == '0')
					zeros++;
				else if (mask[i] == 'X')
					break;
			}

			// Count crosses
			for (unsigned i = 0; i < mask.size(); i++) {
				if (mask[i] == 'X')
					crosses++;
			}

			startAddress = zeros / 2;
			size = crosses / 2;

			printf("Start: %llu, size %zu\n", (unsigned long long)startAddress, size);

			return true;
		}

		std::string verifyMaskList(const std::string &mask, HexView::LineOffsetList_t lst)
		{
			unsigned i = 0;
			unsigned startX = 0;
			unsigned xCount = 0;
			unsigned line = 0;

			while (1) {
				if (i == mask.size())
					break;

				char curChar = toupper(mask[i]);
				char nextChar = toupper(mask[i + 1]);

				if (startX != 0) {
					if (!(curChar == 'X' || (curChar == ' ' && nextChar == 'X'))) {
						printf("X ending at %u\n", i);
						if (lst.empty())
							return "List empty";

						HexView::LineOffset cur = lst.front();
						lst.pop_front();

						printf("  Comparing: offset %u/%u, count %u/%u, line %u/%u\n",
								cur.m_offset, startX, cur.m_count, xCount, cur.m_line, line);
						if (cur.m_offset != startX ||
								cur.m_count != xCount ||
								cur.m_line != line)
							return fmt("offset %u/%u, count %u/%u, line %u/%u\n",
								cur.m_offset, startX, cur.m_count, xCount, cur.m_line, line);

						xCount = 0;
						startX = 0;
					} else {
						xCount++;
					}
				} else if (curChar == 'X') {
					printf("X starting at %u\n", i);
					startX = (i % 86);
					xCount = 1;
				}

				if (curChar == '\n') {
					line++;
				}

				i++;
			}

			if (!lst.empty())
				return fmt("Entries still left in the list: %u\n", (unsigned)lst.size());

			return "";
		}

		std::string verify(std::string mask, unsigned width)
		{
			uint64_t start;
			size_t size;
			HexView h;

			h.m_addressToLineMap[0] = 0;
			h.m_addressToLineMap[0x10] = 1;

			printf("\n");
			bool res = getStartAndSize(mask, start, size);

			if (!res)
				return "Can't get size and mask";

			HexView::LineOffsetList_t lst = h.getMarkRegions(start, size, width);

			return verifyMaskList(mask, lst);
		}
	};

	static uint8_t data[] =
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

		h.setData((void *)data, 0x1000, sizeof(data));

		std::string s8LE = h.handleAllData(8, true, true);
		std::string s8BE = h.handleAllData(8, false, false);
		std::string s16LE = h.handleAllData(16, true, false);
		std::string s16BE = h.handleAllData(16, false, false);
		std::string s32BE = h.handleAllData(32, false, false);
		std::string s64BE = h.handleAllData(64, false, false);

		ASSERT_TRUE(s8LE == s8BE);
		ASSERT_TRUE(s8LE ==  "0x0000000000001000  00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff  ..\"3DUfw........\n");
		ASSERT_TRUE(h.m_addressToLineMap[0x1000] == 0ULL);

		ASSERT_TRUE(s16LE != s16BE);
		ASSERT_TRUE(s16BE == "0x0000000000001000  0011 2233 4455 6677 8899 aabb ccdd eeff          ..\"3DUfw........\n");
		ASSERT_TRUE(s32BE == "0x0000000000001000  00112233 44556677 8899aabb ccddeeff              ..\"3DUfw........\n");
		ASSERT_TRUE(s64BE == "0x0000000000001000  0011223344556677 8899aabbccddeeff                ..\"3DUfw........\n");
	}

	TEST(markSelfTest, MarkFixture)
	{
		std::string selfTest = "000000000000000000  00 00 00 00 00 00 00 00 XX XX 00 00 00 00 00 00  ........xx.......\n";
		std::string s;
		bool res;

		uint64_t start;
		size_t size;
		HexView h;

		h.m_addressToLineMap[0] = 0;
		h.m_addressToLineMap[0x10] = 1;

		res = getStartAndSize(selfTest, start, size);
		ASSERT_TRUE(res);
		HexView::LineOffsetList_t lst;
		lst.push_back(HexView::LineOffset(0, 44, 5));
		lst.push_back(HexView::LineOffset(0, 77, 2));
		s = verifyMaskList(selfTest, lst);
		ASSERT_TRUE(s == "");
	}

	TEST(mark, MarkFixture)
	{
		std::string s;

		s = verify("000000000000000000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  .................\n", 8);
		ASSERT_TRUE(s == "");

		s = verify("000000000000000000  00 00 00 00 00 00 00 00 00 XX XX 00 00 00 00 00  .........xx......\n", 8);
		ASSERT_TRUE(s == "");

		s = verify("000000000000000000  0000 0000 0000 0000 XXXX 0000 0000 0000          ........xx.......\n", 16);
		ASSERT_TRUE(s == "");

		s = verify("000000000000000000  00000000 00000000 XXXX0000 00000000              ........xx.......\n", 32);
		ASSERT_TRUE(s == "");

		s = verify("000000000000000000  0000 0000 0000 0000 0000 0000 0000 00XX          ...............x\n"
				   "000000000000000010  XXXX 0000 0000 0000 0000 0000 0000 0000          xx..............\n", 16);
		ASSERT_TRUE(s == "");
	}
}
