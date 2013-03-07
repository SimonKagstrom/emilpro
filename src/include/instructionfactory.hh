#pragma once

#include <architecturefactory.hh>
#include <iinstruction.hh>
#include <xmlfactory.hh>

#include <vector>
#include <string>

#include <unordered_map>

// unit test
namespace instruction_factory
{
	class instructionModelXml;
}

namespace emilpro
{
	class InstructionModel;

	class InstructionFactory : public ArchitectureFactory::IArchitectureListener
	{
	public:
		friend class instruction_factory::instructionModelXml;

		class IEncodingHandler
		{
		public:
			virtual ~IEncodingHandler()
			{
			}

			virtual std::string getMnemonic(std::vector<std::string> encodingVector) = 0;
		};

		InstructionFactory();

		void destroy();

		static InstructionFactory &instance();

		IInstruction *create(uint64_t address, std::vector<std::string> encodingVector,
				std::string &encoding, uint8_t *data, size_t size);

		virtual void onArchitectureDetected(ArchitectureFactory::Architecture_t arch);

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
			InstructionModel *m_currentModel;
		};


		typedef std::unordered_map<unsigned, IEncodingHandler *> ArchitectureToEncoding_t;
		typedef std::unordered_map<std::string, InstructionModel*> MnemonicToModel_t;
		typedef std::unordered_map<unsigned, MnemonicToModel_t> ArchitectureToModelMap_t;

		IEncodingHandler *m_encodingHandler;
		IEncodingHandler *m_genericEncodingHandler;
		ArchitectureToEncoding_t m_encodingMap;
		ArchitectureToModelMap_t m_instructionModelByArchitecture;

		ArchitectureFactory::Architecture_t m_currentArchitecture;
		XmlListener m_xmlListener;
	};
}
