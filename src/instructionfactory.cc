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
	uint64_t getAddress() const
	{
		return m_address;
	}

	uint64_t getSize() const
	{
		return m_size;
	}

	uint64_t getBranchTargetAddress() const
	{
		return m_targetAddress;
	}

	Ternary_t isPrivileged() const
	{
		return m_privileged;
	}

	InstructionType_t getType() const
	{
		return m_type;
	}

	const std::string &getString() const
	{
		return m_encoding;
	}

	const std::string &getMnemonic() const
	{
		return m_mnemonic;
	}

	const OperandList_t &getOperands() const
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
	InstructionModel(const std::string &mnemonic, std::string &architecture) :
		m_mnemonic(mnemonic),
		m_type(IInstruction::IT_UNKNOWN),
		m_privileged(T_unknown),
		m_description(""),
		m_addressReferenceIndex(IInstructionModel::IDX_GUESS),
		m_timestamp(0)
	{
		m_architecture = ArchitectureFactory::instance().getArchitectureFromName(architecture);
	}

	void setType(const std::string &typeStr)
	{
		if (typeStr == "cflow")
			m_type = IInstruction::IT_CFLOW;
		else if (typeStr == "call")
			m_type = IInstruction::IT_CALL;
		else if (typeStr == "data_handling")
			m_type = IInstruction::IT_DATA_HANDLING;
		else if (typeStr == "arithmetic_logic")
			m_type = IInstruction::IT_ARITHMETIC_LOGIC;
		else if (typeStr == "other")
			m_type = IInstruction::IT_OTHER;
		else
			m_type = IInstruction::IT_UNKNOWN;
	}

	void setType(IInstruction::InstructionType_t type)
	{
		m_type = type;
	}

	void setPrivileged(const std::string &privilegedStr)
	{
		if (privilegedStr == "true")
			m_privileged = T_true;
		else if (privilegedStr == "false")
			m_privileged = T_false;
		else
			m_privileged = T_unknown;
	}

	void setPrivileged(Ternary_t privileged)
	{
		m_privileged = privileged;
	}

	void setDescription(const std::string &description)
	{
		m_description = description;
	}

	void setAddressReferenceIndex(int index)
	{
	}

	void setTimeStamp(uint64_t ts)
	{
		m_timestamp = ts;
	}

	uint64_t getTimeStamp() const
	{
		return m_timestamp;
	}

	IInstruction::InstructionType_t getType() const
	{
		return m_type;
	}

	Ternary_t isPrivileged() const
	{
		return m_privileged;
	}

	const std::string &getDescription() const
	{
		return m_description;
	}

	int getAddressReferenceIndex() const
	{
		return m_addressReferenceIndex;
	}

	ArchitectureFactory::Architecture_t getArchitecture() const
	{
		return m_architecture;
	}

	std::string toXml()
	{
		return fmt(
				"  <InstructionModel name=\"%s\" architecture=\"%s\" timestamp=\"%llu\">\n"
				"    <type>%s</type>\n"
				"    <privileged>%s</privileged>\n"
				"    <description>%s</description>\n"
				"  </InstructionModel>\n",
				escape_string_for_xml(m_mnemonic).c_str(),
				ArchitectureFactory::instance().getNameFromArchitecture(m_architecture).c_str(),
				(unsigned long long)m_timestamp,
				getTypeString().c_str(),
				getPrivilegeString().c_str(),
				escape_string_for_xml(m_description).c_str()
				);
	}

//private:
	std::string getTypeString()
	{
		switch (m_type)
		{
		case IInstruction::IT_CFLOW:
			return "cflow";
		case IInstruction::IT_CALL:
			return "call";
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
	uint64_t m_timestamp;
};

class GenericEncodingHandler : public InstructionFactory::IEncodingHandler
{
public:
	virtual std::string getMnemonic(std::vector<std::string> encodingVector)
	{
		return encodingVector[0];
	}

	virtual const std::vector<std::string> mangleEncodingVector(std::vector<std::string> encodingVector)
	{
		return encodingVector;
	}
};

class ArmEncodingHandler : public GenericEncodingHandler
{
public:
	virtual const std::vector<std::string> mangleEncodingVector(std::vector<std::string> encodingVector)
	{
		std::vector<std::string> out;

		std::string cur;
		for (std::vector<std::string>::iterator it = encodingVector.begin();
				it != encodingVector.end();
				++it) {
			std::string s = *it;

			if (s[0] == ',' || s[0] == ' ' || s[0] == '\t') {
				out.push_back(cur);
				cur = "";
			}

			cur += s;
		}

		if (cur != "")
			out.push_back(cur);

		return out;
	}
};

class I386EncodingHandler : public GenericEncodingHandler
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

class PowerPCEncodingHandler : public GenericEncodingHandler
{
public:
	virtual const std::vector<std::string> mangleEncodingVector(std::vector<std::string> encodingVector)
	{
		std::vector<std::string> out;

		std::string cur;
		size_t sz = encodingVector.size();

		unsigned i = 0;
		for (std::vector<std::string>::iterator it = encodingVector.begin();
				it != encodingVector.end();
				++it) {
			std::string s = *it;

			cur += s;
			if (s == "," || i == 0 || (i == sz - 1)) {
				out.push_back(cur);
				cur = "";
			}
			i++;
		}

		return out;
	}
};

InstructionFactory::InstructionFactory() :
		m_instructionModelByArchitecture(),
		m_xmlListener(this)
{
	m_encodingMap[bfd_arch_arm] = new ArmEncodingHandler();
	m_encodingMap[bfd_arch_i386] = new I386EncodingHandler();
	m_encodingMap[bfd_arch_powerpc] = new PowerPCEncodingHandler();
	m_genericEncodingHandler = new GenericEncodingHandler();
	m_encodingHandler = m_genericEncodingHandler;

	ArchitectureFactory::instance().registerListener(this);
}

IInstruction* InstructionFactory::create(uint64_t startAddress, uint64_t pc, std::vector<std::string> &encodingVector,
		std::string& encoding, uint8_t *data, size_t size)
{
	std::lock_guard<std::mutex> lock(m_mutex);

	if (encodingVector.size() == 0)
		return NULL;

	encodingVector = m_encodingHandler->mangleEncodingVector(encodingVector);

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
				int64_t offset = string_to_integer(cur);

				if (size < 8 && (offset & (1 << 31)))
					offset |= 0xffffffff00000000ULL;

				targetAddress = startAddress + offset;
				break;
			}
		}
	}

	return new Instruction(startAddress + pc, targetAddress, type, encoding, mnemonic, privileged, data, size);
}

static InstructionFactory *g_instance;
void InstructionFactory::destroy()
{
	m_mutex.lock();
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

	m_mutex.unlock();

	delete this;
}

InstructionFactory& InstructionFactory::instance()
{
	static std::mutex instanceMutex;

	instanceMutex.lock();
	if (!g_instance)
		g_instance = new InstructionFactory();
	instanceMutex.unlock();

	return *g_instance;
}

void InstructionFactory::onArchitectureDetected(ArchitectureFactory::Architecture_t arch,
		ArchitectureFactory::Machine_t)
{
	std::lock_guard<std::mutex> lock(m_mutex);

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
	std::lock_guard<std::mutex> lock(m_parent->m_mutex);

	if (name == "InstructionModel") {
		if (m_currentModel)
			delete m_currentModel;

		std::string instructionName;
		std::string instructionArchitecture;
		uint64_t timestamp = get_utc_timestamp();

		for(xmlpp::SaxParser::AttributeList::const_iterator it = properties.begin();
				it != properties.end();
				++it) {
			if (it->name == "name") {
				instructionName = it->value;
			} else if (it->name == "architecture") {
				instructionArchitecture = it->value;
			} else if (it->name == "timestamp") {
				if (string_is_integer(it->value))
					timestamp = string_to_integer(it->value);
			}
		}

		if (instructionName == "" || instructionArchitecture == "")
			return false;

		m_currentModel = new InstructionModel(instructionName, instructionArchitecture);
		m_currentModel->setTimeStamp(timestamp);
	}

	return true;
}

bool InstructionFactory::XmlListener::onElement(const Glib::ustring& name,
		const xmlpp::SaxParser::AttributeList& properties, std::string value)
{
	std::lock_guard<std::mutex> lock(m_parent->m_mutex);

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
	std::lock_guard<std::mutex> lock(m_parent->m_mutex);

	if (name == "InstructionModel") {
		if (!m_currentModel)
			return false;

		InstructionModel *p = (InstructionModel *)m_currentModel;

		InstructionFactory::MnemonicToModel_t &curMap = m_parent->m_instructionModelByArchitecture[(unsigned)p->m_architecture];
		InstructionModel *previousModel = (InstructionModel *)curMap[p->m_mnemonic];

		if (!previousModel) {
			curMap[p->m_mnemonic] = m_currentModel;
		} else {
			if (p->m_timestamp >= previousModel->m_timestamp) {
				delete previousModel;
				curMap[p->m_mnemonic] = m_currentModel;
			} else {
				delete m_currentModel;
			}
		}

		m_currentModel = NULL;
	}
	return true;
}

InstructionFactory::IInstructionModel* InstructionFactory::getModelFromInstruction(const IInstruction &insn)
{
	std::lock_guard<std::mutex> lock(m_mutex);

	InstructionFactory::MnemonicToModel_t &archModel = m_instructionModelByArchitecture[(unsigned)m_currentArchitecture];

	return archModel[insn.getMnemonic()];
}

InstructionFactory::IInstructionModel* InstructionFactory::createModelForInstruction(const IInstruction& insn)
{
	std::lock_guard<std::mutex> lock(m_mutex);

	InstructionFactory::IInstructionModel *out = new InstructionModel(insn.getMnemonic(),
			ArchitectureFactory::instance().getNameFromArchitecture(m_currentArchitecture));

	InstructionFactory::MnemonicToModel_t &archModel = m_instructionModelByArchitecture[(unsigned)m_currentArchitecture];
	archModel[insn.getMnemonic()] = out;

	return out;
}

InstructionFactory::InstructionModelList_t InstructionFactory::getInstructionModels(uint64_t fromTimestamp)
{
	std::lock_guard<std::mutex> lock(m_mutex);

	InstructionFactory::InstructionModelList_t out;
	std::map<std::string, InstructionModelList_t> byMnemonic;

	for (InstructionFactory::ArchitectureToModelMap_t::iterator it = m_instructionModelByArchitecture.begin();
			it != m_instructionModelByArchitecture.end();
			++it) {
		InstructionFactory::MnemonicToModel_t &cur = it->second;

		for (InstructionFactory::MnemonicToModel_t::iterator itModel = cur.begin();
				itModel != cur.end();
				++itModel) {
			InstructionModel *p = (InstructionModel *)itModel->second;

			// Instructions found in the file, but no model for these
			if (!p)
				continue;

			if (p->m_timestamp >= fromTimestamp)
				byMnemonic[p->m_mnemonic].push_back(p);
		}
	}

	for (std::map<std::string, InstructionModelList_t>::iterator it = byMnemonic.begin();
			it != byMnemonic.end();
			++it) {
		for (InstructionFactory::InstructionModelList_t::iterator lstIt = it->second.begin();
				lstIt != it->second.end();
				++lstIt) {
			out.push_back(*lstIt);
		}
	}

	return out;
}
