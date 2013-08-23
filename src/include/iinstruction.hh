#pragma once

#include <stdint.h>
#include <string>
#include <list>
#include <map>

#include "iobject.hh"

namespace emilpro
{
	typedef enum
	{
		T_false = false,
		T_true = true,
		T_unknown,
	} Ternary_t;


	class IOperand
	{
	public:
		typedef enum
		{
			OP_UNKNOWN,
			OP_REGISTER,
			OP_ADDRESS,
			OP_IMMEDIATE
		} OperandType_t;

		virtual ~IOperand()
		{
		}

		virtual Ternary_t isTarget() const = 0;

		virtual OperandType_t getType() const = 0;

		virtual uint64_t getValue() const = 0;

		virtual const std::string &getString() const = 0;
	};

	class IInstruction : public IObject
	{
	public:
		enum
		{
			INVALID_ADDRESS = 0xfffffffffffffffbULL,
		};

		typedef enum
		{
			IT_UNKNOWN,
			IT_CFLOW,
			IT_CALL,
			IT_DATA_HANDLING,
			IT_ARITHMETIC_LOGIC,
			IT_OTHER,
		} InstructionType_t;

		typedef std::list<IOperand *> OperandList_t;


		virtual ~IInstruction()
		{
		}

		virtual uint64_t getAddress() = 0;

		virtual uint64_t getSize() = 0;

		/**
		 * Return the target address for branches/calls.
		 */
		virtual uint64_t getBranchTargetAddress() = 0;

		virtual Ternary_t isPrivileged() = 0;

		virtual InstructionType_t getType() = 0;

		virtual std::string &getString() = 0;

		virtual std::string &getMnemonic() = 0;

		virtual const OperandList_t &getOperands() = 0;
	};

	typedef std::list<IInstruction *> InstructionList_t;
	typedef std::map<uint64_t, IInstruction *> InstructionMap_t;
}
