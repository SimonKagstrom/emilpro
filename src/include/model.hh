#pragma once

#include "iinstruction.hh"
#include "ilineprovider.hh"
#include "symbolfactory.hh"
#include "isymbol.hh"

#include <mutex>
#include <thread>
#include <list>
#include <map>
#include <unordered_map>

// Forward declare the unit test stuff (which befriends this class)
namespace model
{
	class disassembleInstructions;
	class sourceLines;
	class workerThreads;
}

namespace emilpro
{
	class Model : private ISymbolListener
	{
	public:
		class IBasicBlock
		{
		public:
			virtual ~IBasicBlock()
			{
			}

			virtual InstructionList_t getInstructions() = 0;
		};

		friend class model::disassembleInstructions;
		friend class model::sourceLines;
		friend class model::workerThreads;

		typedef std::list<IBasicBlock *> BasicBlockList_t;
		typedef std::list<ISymbol *> SymbolList_t;
		typedef std::list<uint64_t> CrossReferenceList_t;

		bool addData(void *data, size_t size);


		/**
		 * Return pointer to memory (instructions or data). Should not be free:d.
		 */
		const uint8_t *getData(uint64_t start, size_t size);

		const InstructionList_t getInstructions(uint64_t start, uint64_t end);

		BasicBlockList_t getBasicBlocksFromInstructions(const InstructionList_t &instructions);

		const SymbolList_t &getSymbols();

		void registerSymbolListener(ISymbolListener *listener);

		const SymbolList_t getSymbolExact(uint64_t address);

		const SymbolList_t getNearestSymbol(uint64_t address);

		const ILineProvider::FileLine getLineByAddress(uint64_t addr);

		const CrossReferenceList_t &getReferences(uint64_t addr) const;

		void destroy();


		void parseAll();

		bool parsingComplete();

		static Model &instance();

	private:
		class DataChunk
		{
		public:
			DataChunk(uint64_t address, uint64_t fileOffset, uint64_t size, uint8_t *data) :
				m_address(address),
				m_fileOffset(fileOffset),
				m_size(size),
				m_data(data)
			{
			}


			const uint64_t m_address;
			const uint64_t m_fileOffset;
			const size_t m_size;
			const uint8_t *m_data;
		};

		typedef std::map<uint64_t, SymbolList_t> SymbolOrderedMap_t;
		typedef std::unordered_map<uint64_t, SymbolList_t> SymbolMap_t;
		typedef std::unordered_map<uint64_t, ILineProvider::FileLine> AddressFileLineMap_t;
		typedef std::list<ISymbol *> SymbolQueue_t;
		typedef std::list<ISymbolListener *> SymbolListeners_t;
		typedef std::map<uint64_t, DataChunk *> DataMap_t;

		typedef std::unordered_map<uint64_t, CrossReferenceList_t> CrossReferenceMap_t;

		Model();
		virtual ~Model();

		bool parsingOngoing();

		void fillCacheWithSymbol(ISymbol *sym);

		void deriveSymbols(ISymbol *sym, InstructionList_t &lst);

		void addDerivedSymbol(uint64_t address, int64_t size, void *data);

		const ILineProvider::FileLine getLineByAddressLocked(uint64_t addr);

		const SymbolList_t &getSymbolsLocked();

		const SymbolList_t getSymbolExactLocked(uint64_t address);

		const SymbolList_t getNearestSymbolLocked(uint64_t address);

		void worker(unsigned queueNr);


		// From ISymbolListener
		void onSymbol(ISymbol &sym);

		std::mutex m_mutex;
		InstructionMap_t m_instructionCache;
		SymbolOrderedMap_t m_orderedSymbols;
		SymbolMap_t m_symbolsByAddress;
		SymbolList_t m_symbols;
		AddressFileLineMap_t m_fileLineCache;
		DataMap_t m_data;
		CrossReferenceMap_t m_crossReferences;
		CrossReferenceList_t m_emptyReferenceList;
		SymbolListeners_t m_symbolListeners;

		SymbolList_t m_pendingListenerSymbols;

		std::thread **m_threads;
		SymbolList_t *m_workQueues;
		bool m_parsingComplete;
		bool m_quit;
	};
}
