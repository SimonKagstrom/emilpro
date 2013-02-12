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

		bool addData(void *data, size_t size);


		/**
		 * Return pointer to memory (instructions or data). Should not be free:d.
		 */
		const uint8_t *getData(uint64_t start, uint64_t end);

		const InstructionList_t getInstructions(uint64_t start, uint64_t end);

		BasicBlockList_t getBasicBlocksFromInstructions(const InstructionList_t &instructions);

		const SymbolList_t &getSymbols();

		const ISymbol *getSymbol(uint64_t address);

		const ILineProvider::FileLine getLineByAddress(uint64_t addr);

		void destroy();


		void parseAll();

		bool parsingComplete();

		static Model &instance();

	private:
		typedef std::map<uint64_t, ISymbol *> SymbolOrderedMap_t;
		typedef std::unordered_map<uint64_t, ILineProvider::FileLine> AddressFileLineMap_t;
		typedef std::list<ISymbol *> SymbolQueue_t;

		Model();
		virtual ~Model();

		void fillCacheWithSymbol(ISymbol *sym);

		const ILineProvider::FileLine getLineByAddressLocked(uint64_t addr);

		const SymbolList_t &getSymbolsLocked();

		const ISymbol *getSymbolLocked(uint64_t address);

		void worker(unsigned queueNr);


		// From ISymbolListener
		void onSymbol(ISymbol &sym);

		std::mutex m_mutex;
		InstructionMap_t m_instructionCache;
		SymbolOrderedMap_t m_orderedSymbols;
		SymbolList_t m_symbols;
		AddressFileLineMap_t m_fileLineCache;
		uint8_t *m_memory;

		std::thread **m_threads;
		SymbolList_t *m_workQueues;
	};
}
