#pragma once

#include <architecturefactory.hh>
#include <iinstruction.hh>

#include <vector>
#include <string>

#include <unordered_map>

namespace emilpro
{
	class InstructionFactory : public ArchitectureFactory::IArchitectureListener
	{
	public:
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
		typedef std::unordered_map<unsigned, IEncodingHandler *> ArchitectureToEncoding_t;

		IEncodingHandler *m_encodingHandler;
		IEncodingHandler *m_genericEncodingHandler;
		ArchitectureToEncoding_t m_encodingMap;
	};
}
