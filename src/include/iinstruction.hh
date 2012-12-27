#pragma once

#include <stdint.h>
#include <string>
#include <list>

namespace emilpro
{
	class IOperand
	{
	public:
		virtual ~IOperand()
		{
		}

		virtual std::string &getEncoding() = 0;
	};

	class IInstruction
	{
	public:
		typedef enum
		{
			IT_UNKNOWN,
			IT_CFLOW,
			IT_DATA_HANDLING,
			IT_ARITHMETIC_LOGIC,
			IT_OTHER,
		} InstructionType_t;

		typedef enum
		{
			T_false = false,
			T_true = true,
			T_unknown,
		} Ternary_t;

		typedef std::list<const IOperand *> OperandList_t;


		virtual ~IInstruction()
		{
		}

		virtual uint64_t getAddress() = 0;

		virtual Ternary_t isPrivileged() = 0;

		virtual InstructionType_t getType() = 0;

		virtual std::string &getEncoding() = 0;

		virtual const OperandList_t &getOperands() = 0;
	};
}
