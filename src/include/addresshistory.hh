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

			virtual std::string getName() const = 0;

			virtual uint64_t getAddress() const = 0;


			virtual bool isValid() const = 0;
		};

		AddressHistory();

		~AddressHistory();


		bool maybeAddEntry(uint64_t address);

		void clear();


		const Entry &current();

		const Entry &back();

		const Entry &forward();

	private:
		typedef std::vector<Entry *> EntryVector_t;

		EntryVector_t m_entries;
		int m_currentEntry;

		Entry *m_sentinel;
	};
}
