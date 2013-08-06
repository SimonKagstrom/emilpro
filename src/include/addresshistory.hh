#pragma once

#include <vector>
#include <string>

namespace emilpro
{
	class AddressHistory
	{
	public:
		class Entry
		{
		public:
			virtual ~Entry()
			{
			}

			virtual std::string getName() = 0;

			virtual uint64_t getAddress() = 0;


			virtual bool isValid() = 0;
		};

		AddressHistory();

		~AddressHistory();


		bool maybeAddEntry(uint64_t address);

		void clear();


		Entry &current();

		Entry &back();

		Entry &forward();

	private:
		typedef std::vector<Entry *> EntryVector_t;

		EntryVector_t m_entries;
		int m_currentEntry;

		Entry *m_sentinel;
	};
}
