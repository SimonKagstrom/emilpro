#include <instructionfactory.hh>

#include <string.h>
#include <stdlib.h>

using namespace emilpro;


class Operand : public IOperand
{
public:
	Operand(const char *encoding, Ternary_t isTarget, OperandType_t type, uint64_t value) :
		m_encoding(encoding), m_isTarget(isTarget), m_type(type), m_value(value)
	{
	}

	Ternary_t isTarget() const
	{
		return m_isTarget;
	}

	OperandType_t getType() const
	{
		return m_type;
	}

	const std::string &getString() const
	{
		return m_encoding;
	}

	uint64_t getValue() const
	{
		return m_value;
	}

private:
	std::string m_encoding;
	Ternary_t m_isTarget;
	OperandType_t m_type;
	uint64_t m_value;
};

class Instruction : public IInstruction
{
public:
	Instruction(uint64_t address, uint64_t targetAddress, InstructionType_t type, std::string &encoding,
			std::string &mnemonic, Ternary_t privileged, uint8_t *ptr, uint64_t size) :
		m_address(address),
		m_targetAddress(targetAddress),
		m_type(type),
		m_encoding(encoding),
		m_mnemonic(mnemonic),
		m_privileged(privileged),
		m_size(size)
	{
		m_ptr = new uint8_t[m_size];

		memcpy(m_ptr, ptr, m_size);
	}

	virtual ~Instruction()
	{
		delete []m_ptr;

		for (OperandList_t::iterator it = m_operands.begin();
				it != m_operands.end();
				it++)
			delete *it;
	}

	void addOperand(Operand *op)
	{
		m_operands.push_back(op);
	}

	// From IInstruction
	uint64_t getAddress()
	{
		return m_address;
	}

	uint64_t getSize()
	{
		return m_size;
	}

	uint64_t getBranchTargetAddress()
	{
		return m_targetAddress;
	}

	Ternary_t isPrivileged()
	{
		return m_privileged;
	}

	InstructionType_t getType()
	{
		return m_type;
	}

	std::string &getString()
	{
		return m_encoding;
	}

	std::string &getMnemonic()
	{
		return m_mnemonic;
	}

	const OperandList_t &getOperands()
	{
		return m_operands;
	}

	uint8_t *getRawData(size_t &sz)
	{
		sz = m_size;

		return m_ptr;
	}

private:
	uint64_t m_address;
	uint64_t m_targetAddress;
	InstructionType_t m_type;
	std::string m_encoding;
	std::string m_mnemonic;
	Ternary_t m_privileged;
	uint64_t m_size;
	uint8_t *m_ptr;

	IInstruction::OperandList_t m_operands;
};


InstructionFactory::InstructionFactory()
{
}

IInstruction* InstructionFactory::create(uint64_t address, std::vector<std::string> encodingVector,
		std::string& encoding, uint8_t *data, size_t size)
{
	if (encodingVector.size() == 0)
		return NULL;

	std::string &mnemonic = encodingVector[0];
	uint64_t targetAddress = IInstruction::INVALID_ADDRESS;
	IInstruction::InstructionType_t type = IInstruction::IT_UNKNOWN;
	Ternary_t privileged = T_unknown;

	return new Instruction(address, targetAddress, type, encoding, mnemonic, privileged, data, size);
}

static InstructionFactory *g_instance;
void InstructionFactory::destroy()
{
	g_instance = NULL;

	delete this;
}

InstructionFactory& InstructionFactory::instance()
{
	if (!g_instance)
		g_instance = new InstructionFactory();

	return *g_instance;
}

void InstructionFactory::onArchitectureDetected(ArchitectureFactory::Architecture_t arch)
{
}

