#pragma once

#include "iinstruction.hh"
#include "symbolfactory.hh"
#include "isymbol.hh"

#include <list>
#include <map>

// Forward declare the unit test stuff (which befriends this class)
namespace model
{
	class disassembleInstructions;
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

		void destroy();

		static Model &instance();

	private:
		typedef std::map<uint64_t, IInstruction *> InstructionMap_t;
		typedef std::map<uint64_t, ISymbol *> SymbolAddressMap_t;

		Model();
		virtual ~Model();

		void fillCacheWithSymbol(ISymbol *sym);

		// From ISymbolListener
		void onSymbol(ISymbol &sym);

		InstructionMap_t m_instructionCache;
		SymbolAddressMap_t m_symbolsByAddress;
		SymbolList_t m_symbols;
		uint8_t *m_memory;
	};
}
