#include <stdio.h>
#include <stdint.h>
#include <opdis/opdis.h>

#include <map>

#include <bfd.h>

#include <architecturefactory.hh>
#include <idisassembly.hh>
#include <iinstruction.hh>
#include <utils.hh>

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
	Instruction(uint64_t address, uint64_t targetAddress, InstructionType_t type, const char *encoding, const char *mnemonic, Ternary_t privileged, uint8_t *ptr, uint64_t size) :
		m_address(address),
		m_targetAddress(targetAddress),
		m_type(type),
		m_encoding(encoding),
		m_mnemonic(mnemonic),
		m_privileged(privileged),
		m_size(size)
	{
		m_ptr = new uint8_t[m_size];

		mempcpy(m_ptr, ptr, m_size);
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

class Disassembly : public IDisassembly, ArchitectureFactory::IArchitectureListener
{
public:
	Disassembly()
	{
	    m_opdis = NULL;
	    m_list = NULL;
	    m_startAddress = 0;

	    m_arch[bfd_arch_i386] = (BfdArch_t){bfd_arch_i386, print_insn_i386};
#if defined(HAVE_BFD_MULTIARCH)
	    m_arch[bfd_arch_powerpc] = (BfdArch_t){bfd_arch_powerpc, print_insn_big_powerpc};
	    m_arch[bfd_arch_arm] = (BfdArch_t){bfd_arch_arm, print_insn_little_arm};
	    m_arch[bfd_arch_mips] = (BfdArch_t){bfd_arch_mips, print_insn_big_mips};
#endif
	}

	void init()
	{
	    m_opdis = opdis_init();

	    opdis_set_display(m_opdis, opdisDisplayStatic, (void *)this);
	    opdis_set_x86_syntax(m_opdis, opdis_x86_syntax_att); // TMP!

	    ArchitectureFactory::instance().registerListener(this);
	}

	virtual ~Disassembly()
	{
		if (m_opdis)
			opdis_term(m_opdis);
	}

	virtual void onArchitectureDetected(ArchitectureFactory::Architecture_t arch)
	{
		ArchitectureBfdMap_t::iterator it = m_arch.find(arch);

		if (it != m_arch.end())
		{
			BfdArch_t cur = it->second;

			opdis_set_arch(m_opdis, cur.bfd_arch, 0, cur.callback);
		}
	}

	InstructionList_t execute(void *p, size_t size, uint64_t address)
	{
		InstructionList_t out;
		uint8_t *data = (uint8_t *)p;

		if (!data || size == 0)
			return out;

		opdis_buf_t buf = opdis_buf_alloc(size, 0);

		int v = opdis_buf_fill(buf, 0, data, size);

		if (v == (int)size) {
			m_list = &out;
			m_startAddress = address;
			opdis_disasm_linear(m_opdis, buf, 0, size);
		}

		opdis_buf_free(buf);
		m_list = NULL;
		m_startAddress = 0;

		return out;
	}

private:

	void opdisDisplay(const opdis_insn_t *insn)
	{
		panic_if(!m_list,
				"No list when displaying!");

		uint64_t address = m_startAddress + insn->offset;
		uint64_t targetAddress = address;
		IInstruction::InstructionType_t type = IInstruction::IT_UNKNOWN;
		const char *encoding = insn->ascii;
		const char *mnemonic = insn->mnemonic;
		uint8_t *bytes = insn->bytes;
		uint64_t size = insn->size;
		Ternary_t privileged = T_unknown;

		if (insn->status & opdis_decode_mnem_flags) {
			privileged = T_false;

			switch (insn->category)
			{
			case opdis_insn_cat_cflow:
				type = IInstruction::IT_CFLOW;
				break;
			case opdis_insn_cat_lost:
			case opdis_insn_cat_stack:
				type = IInstruction::IT_DATA_HANDLING;
				break;
			case opdis_insn_cat_test:
			case opdis_insn_cat_math:
			case opdis_insn_cat_bit:
				type = IInstruction::IT_ARITHMETIC_LOGIC;
				break;
			case opdis_insn_cat_priv:
				type = IInstruction::IT_OTHER;
				privileged = T_true;
				break;
			default:
				type = IInstruction::IT_OTHER;
				break;
			}
		}

		if ((insn->status & opdis_decode_ops) && insn->target) {

			if (insn->target->category == opdis_op_cat_immediate)
				targetAddress = m_startAddress + (uint64_t)insn->target->value.immediate.vma;

			// Assume a flat address space model
			else if (insn->target->category == opdis_op_cat_absolute)
				targetAddress = (uint64_t)insn->target->value.abs.offset;
		}

		Instruction *cur = new Instruction(address, targetAddress, type, encoding, mnemonic, privileged, bytes, size);

		if (insn->status & opdis_decode_ops) {

			for (unsigned i = 0; i < insn->num_operands; i++) {
				opdis_op_t *op = insn->operands[i];

				Ternary_t isTarget = T_false;
				IOperand::OperandType_t type = IOperand::OP_UNKNOWN;
				uint64_t value = 0;

				if (op->flags == opdis_op_flag_none)
					isTarget = T_unknown;
				if (op->flags & opdis_op_flag_w)
					isTarget = T_true;

				if (op->category == opdis_op_cat_register) {
					type = IOperand::OP_REGISTER;
				} else if (op->category == opdis_op_cat_immediate) {
					type = IOperand::OP_IMMEDIATE;
					value = op->value.immediate.u;
				} else if (op->category == opdis_op_cat_absolute) {
					type = IOperand::OP_ADDRESS;
					value = op->value.abs.offset;
				}

				Operand *p = new Operand(op->ascii, isTarget, type, value);

				cur->addOperand(p);
			}
		}

		m_list->push_back(cur);
	}

	static void opdisDisplayStatic(const opdis_insn_t *insn, void *arg)
	{
	    Disassembly *pThis = (Disassembly *)arg;

	    pThis->opdisDisplay(insn);
	}

	opdis_t m_opdis;
	InstructionList_t *m_list;
	uint64_t m_startAddress;

	typedef struct bfdArch
	{
		enum bfd_architecture bfd_arch;
		disassembler_ftype callback;
	} BfdArch_t;

	typedef std::map<ArchitectureFactory::Architecture_t, struct bfdArch> ArchitectureBfdMap_t;

	ArchitectureBfdMap_t m_arch;
};


IDisassembly &IDisassembly::instance()
{
	static Disassembly *instance;

	if (!instance) {
		instance = new Disassembly();

		instance->init();
	}

	return *instance;
}
