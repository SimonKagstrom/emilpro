#pragma once

#include <architecturefactory.hh>
#include <iinstruction.hh>
#include <xmlfactory.hh>

#include <vector>
#include <string>
#include <mutex>

#include <unordered_map>

// unit test
namespace instruction_factory
{
	class instructionModelXml;
	class modelToFromXml;
	class timestamp;
	class timestampDefault;
}

namespace emilpro
{
	class InstructionModel;

	class InstructionFactory : public ArchitectureFactory::IArchitectureListener
	{
	public:
		friend class instruction_factory::instructionModelXml;
		friend class instruction_factory::modelToFromXml;
		friend class instruction_factory::timestamp;
		friend class instruction_factory::timestampDefault;

		class IEncodingHandler
		{
		public:
			virtual ~IEncodingHandler()
			{
			}

			virtual std::string getMnemonic(std::vector<std::string> encodingVector) = 0;
		};

		class IInstructionModel
		{
		public:
			enum
			{
				IDX_GUESS = -1
			};

			virtual ~IInstructionModel()
			{
			}

			/**
			 * The type of instruction (control-flow, arithmetic etc)
			 */
			virtual void setType(std::string &typeStr) = 0;

			virtual void setType(IInstruction::InstructionType_t type) = 0;

			/**
			 * If the instruction is privileged or not (true/false/unknown)
			 */
			virtual void setPrivileged(std::string &privilegedStr) = 0;

			virtual void setPrivileged(Ternary_t priv) = 0;

			/**
			 * The description (HTML) of what the instruction does.
			 */
			virtual void setDescription(std::string &description) = 0;

			/**
			 * Set the index of the address reference (if applicable). IDX_GUESS to scan and
			 * guess (which is also the default)
			 */
			virtual void setAddressReferenceIndex(int index) = 0;

			virtual void setTimeStamp(uint64_t ts) = 0;


			virtual IInstruction::InstructionType_t getType() = 0;

			virtual Ternary_t isPrivileged() = 0;

			virtual std::string &getDescription() = 0;

			virtual int &getAddressReferenceIndex() = 0;

			virtual uint64_t getTimeStamp() = 0;

			virtual ArchitectureFactory::Architecture_t getArchitecture() = 0;

			/**
			 * Produce XML from the instruction model
			 */
			virtual std::string toXml() = 0;
		};

		typedef std::list<IInstructionModel *> InstructionModelList_t;

		InstructionFactory();

		void destroy();

		static InstructionFactory &instance();

		IInstruction *create(uint64_t startAddress, uint64_t pc, std::vector<std::string> encodingVector,
				std::string &encoding, uint8_t *data, size_t size);

		virtual void onArchitectureDetected(ArchitectureFactory::Architecture_t arch);

		IInstructionModel *getModelFromInstruction(IInstruction &insn);

		IInstructionModel *createModelForInstruction(IInstruction &insn);

		InstructionModelList_t getInstructionModels(uint64_t fromTimestamp = 0);

	private:
		class XmlListener : public XmlFactory::IXmlListener
		{
		public:
			XmlListener(InstructionFactory *parent);

			virtual ~XmlListener();

			virtual bool onStart(const Glib::ustring &name, const xmlpp::SaxParser::AttributeList &properties, std::string value);

			virtual bool onElement(const Glib::ustring &name, const xmlpp::SaxParser::AttributeList &properties, std::string value);

			virtual bool onEnd(const Glib::ustring &name);

		private:
			InstructionFactory *m_parent;
			IInstructionModel *m_currentModel;
		};


		typedef std::unordered_map<unsigned, IEncodingHandler *> ArchitectureToEncoding_t;
		typedef std::unordered_map<std::string, IInstructionModel*> MnemonicToModel_t;
		typedef std::unordered_map<unsigned, MnemonicToModel_t> ArchitectureToModelMap_t;

		IEncodingHandler *m_encodingHandler;
		IEncodingHandler *m_genericEncodingHandler;
		ArchitectureToEncoding_t m_encodingMap;
		ArchitectureToModelMap_t m_instructionModelByArchitecture;

		ArchitectureFactory::Architecture_t m_currentArchitecture;
		XmlListener m_xmlListener;

		std::mutex m_mutex;
	};
}
