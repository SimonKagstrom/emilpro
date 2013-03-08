#include <instructionfactory.hh>
#include <utils.hh>

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


class emilpro::InstructionModel : public InstructionFactory::IInstructionModel
{
public:
	InstructionModel(std::string &mnemonic, std::string &architecture) :
		m_mnemonic(mnemonic),
		m_type(IInstruction::IT_UNKNOWN),
		m_privileged(T_unknown),
		m_description(""),
		m_addressReferenceIndex(IInstructionModel::IDX_GUESS)
	{
		m_architecture = ArchitectureFactory::instance().getArchitectureFromName(architecture);
	}

	void setType(std::string &typeStr)
	{
		if (typeStr == "cflow")
			m_type = IInstruction::IT_CFLOW;
		else if (typeStr == "data_handling")
			m_type = IInstruction::IT_DATA_HANDLING;
		else if (typeStr == "arithmetic_logic")
			m_type = IInstruction::IT_ARITHMETIC_LOGIC;
		else if (typeStr == "other")
			m_type = IInstruction::IT_OTHER;
		else
			m_type = IInstruction::IT_UNKNOWN;
	}

	void setPrivileged(std::string &privilegedStr)
	{
		if (privilegedStr == "true")
			m_privileged = T_true;
		else if (privilegedStr == "false")
			m_privileged = T_false;
		else
			m_privileged = T_unknown;
	}

	void setDescription(std::string &description)
	{
		m_description = description;
	}

	void setAddressReferenceIndex(int index)
	{
	}

	IInstruction::InstructionType_t getType()
	{
		return m_type;
	}

	Ternary_t isPrivileged()
	{
		return m_privileged;
	}

	std::string &getDescription()
	{
		return m_description;
	}

	int &getAddressReferenceIndex()
	{
		return m_addressReferenceIndex;
	}

	std::string toXml()
	{
		return fmt(
				"  <InstructionModel name=\"%s\" architecture=\"%s\">\n"
				"    <type>%s</type>\n"
				"    <privileged>%s</privileged>\n"
				"    <description>%s</description>\n"
				"  </InstructionModel>\n",
				m_mnemonic.c_str(),
				ArchitectureFactory::instance().getNameFromArchitecture(m_architecture).c_str(),
				getTypeString().c_str(),
				getPrivilegeString().c_str(),
				m_description.c_str()
				);
	}

//private:
	std::string getTypeString()
	{
		switch (m_type)
		{
		case IInstruction::IT_CFLOW:
			return "cflow";
		case IInstruction::IT_DATA_HANDLING:
			return "data_handling";
		case IInstruction::IT_ARITHMETIC_LOGIC:
			return "arithmetic_logic";
		case IInstruction::IT_OTHER:
			return "other";
		case IInstruction::IT_UNKNOWN:
		default:
			break;
		}

		return "unknown";
	}

	std::string getPrivilegeString()
	{
		if (m_privileged == T_true)
			return "true";
		else if (m_privileged == T_false)
			return "false";

		return "unknown";
	}

	std::string m_mnemonic;
	IInstruction::InstructionType_t m_type;
	Ternary_t m_privileged;
	std::string m_description;
	ArchitectureFactory::Architecture_t m_architecture;
	int m_addressReferenceIndex;
};

class GenericEncodingHandler : public InstructionFactory::IEncodingHandler
{
public:
	std::string getMnemonic(std::vector<std::string> encodingVector)
	{
		return encodingVector[0];
	}
};

class I386EncodingHandler : public InstructionFactory::IEncodingHandler
{
public:
	std::string getMnemonic(std::vector<std::string> encodingVector)
	{
		if (encodingVector.size() < 2)
			return encodingVector[0];

		if (encodingVector[0] == "lock")
			return encodingVector[1];

		return encodingVector[0];
	}
};

InstructionFactory::InstructionFactory() :
		m_instructionModelByArchitecture(),
		m_xmlListener(this)
{
	m_encodingMap[bfd_arch_i386] = new I386EncodingHandler();
	m_genericEncodingHandler = new GenericEncodingHandler();
	m_encodingHandler = m_genericEncodingHandler;

	ArchitectureFactory::instance().registerListener(this);
}

IInstruction* InstructionFactory::create(uint64_t startAddress, uint64_t pc, std::vector<std::string> encodingVector,
		std::string& encoding, uint8_t *data, size_t size)
{
	if (encodingVector.size() == 0)
		return NULL;


	std::string mnemonic = m_encodingHandler->getMnemonic(encodingVector);
	uint64_t targetAddress = IInstruction::INVALID_ADDRESS;
	IInstruction::InstructionType_t type = IInstruction::IT_UNKNOWN;
	Ternary_t privileged = T_unknown;
	int addressReferenceIndex = IInstructionModel::IDX_GUESS;

	InstructionFactory::MnemonicToModel_t &cur = m_instructionModelByArchitecture[(unsigned)m_currentArchitecture];
	InstructionModel *insnModel = (InstructionModel *)cur[mnemonic];

	if (insnModel) {
		type = insnModel->getType();
		privileged = insnModel->isPrivileged();
		addressReferenceIndex = insnModel->getAddressReferenceIndex();
	}

	if (addressReferenceIndex == IInstructionModel::IDX_GUESS) {
		for (std::vector<std::string>::iterator it = encodingVector.begin();
				it != encodingVector.end();
				++it) {
			std::string &cur = *it;

			if (string_is_integer(cur)) {
				targetAddress = startAddress + string_to_integer(cur);
				break;
			}
		}
	}

	return new Instruction(startAddress + pc, targetAddress, type, encoding, mnemonic, privileged, data, size);
}

static InstructionFactory *g_instance;
void InstructionFactory::destroy()
{
	g_instance = NULL;
	for (InstructionFactory::ArchitectureToEncoding_t::iterator it = m_encodingMap.begin();
			it != m_encodingMap.end();
			++it) {
		delete it->second;
	}
	for (InstructionFactory::ArchitectureToModelMap_t::iterator it = m_instructionModelByArchitecture.begin();
			it != m_instructionModelByArchitecture.end();
			++it) {
		InstructionFactory::MnemonicToModel_t &cur = it->second;

		for (InstructionFactory::MnemonicToModel_t::iterator itModel = cur.begin();
				itModel != cur.end();
				++itModel) {
			InstructionModel *p = (InstructionModel *)itModel->second;

			delete p;
		}
	}

	delete m_genericEncodingHandler;

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
	InstructionFactory::ArchitectureToEncoding_t::iterator it = m_encodingMap.find((unsigned)arch);

	if (it == m_encodingMap.end())
		m_encodingHandler = m_genericEncodingHandler;
	else
		m_encodingHandler = it->second;

	m_currentArchitecture = arch;
}

InstructionFactory::XmlListener::XmlListener(InstructionFactory* parent) :
		m_parent(parent),
		m_currentModel(NULL)
{
	XmlFactory::instance().registerListener("InstructionModel", this);
}

InstructionFactory::XmlListener::~XmlListener()
{
	if (m_currentModel)
		delete m_currentModel;
}

bool InstructionFactory::XmlListener::onStart(const Glib::ustring& name,
		const xmlpp::SaxParser::AttributeList& properties, std::string value)
{
	if (name == "InstructionModel") {
		if (m_currentModel)
			delete m_currentModel;

		std::string instructionName;
		std::string instructionArchitecture;

		for(xmlpp::SaxParser::AttributeList::const_iterator it = properties.begin();
				it != properties.end();
				++it) {
			if (it->name == "name")
				instructionName = it->value;
			else if (it->name == "architecture")
				instructionArchitecture = it->value;
		}

		if (instructionName == "" || instructionArchitecture == "")
			return false;

		m_currentModel = new InstructionModel(instructionName, instructionArchitecture);
	}

	return true;
}

bool InstructionFactory::XmlListener::onElement(const Glib::ustring& name,
		const xmlpp::SaxParser::AttributeList& properties, std::string value)
{
	if (!m_currentModel)
		return false;

	InstructionModel *p = (InstructionModel *)m_currentModel;

	if (name == "type")
		p->setType(value);
	else if (name == "privileged")
		p->setPrivileged(value);
	else if (name == "description")
		p->setDescription(value);

	return true;
}

bool InstructionFactory::XmlListener::onEnd(const Glib::ustring& name)
{
	if (name == "InstructionModel") {
		if (!m_currentModel)
			return false;

		InstructionModel *p = (InstructionModel *)m_currentModel;

		InstructionFactory::MnemonicToModel_t &cur = m_parent->m_instructionModelByArchitecture[(unsigned)p->m_architecture];
		cur[p->m_mnemonic] = m_currentModel;

		m_currentModel = NULL;
	}
	return true;
}

InstructionFactory::IInstructionModel* InstructionFactory::getModelFromInstruction(IInstruction &insn)
{
	InstructionFactory::MnemonicToModel_t &archModel = m_instructionModelByArchitecture[(unsigned)m_currentArchitecture];

	return archModel[insn.getMnemonic()];
}

