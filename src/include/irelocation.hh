#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string>

namespace emilpro
{
	class ISymbol;

	class IRelocation
	{
	public:
		enum RelocationType
		{
			RELOC_PCREL,
			RELOC_ABS,
		};

		virtual ~IRelocation()
		{
		}

		/**
		 * Get the address the relocation will be applied to
		 *
		 * Typically not on the instruction boundary, but somewhere within.
		 *
		 * @return the address
		 */
		virtual uint64_t getSourceAddress() const = 0;

		/**
		 * Size of the relocation.
		 *
		 * The size in bytes of the relocation (i.e., what it replaces)
		 *
		 * @return the size
		 */
		virtual size_t getSize() const = 0;

		/**
		 * The destination of the relocation
		 *
		 * @return the symbol (can also be a section)
		 */
		virtual const ISymbol &getTargetSymbol() const = 0;

		/**
		 * Get the offset from the symbol above.
		 *
		 * @return the offset
		 */
		virtual int64_t getTargetOffset() const = 0;
	};
}
