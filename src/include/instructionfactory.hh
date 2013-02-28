#pragma once

#include <architecturefactory.hh>
#include <iinstruction.hh>

#include <vector>
#include <string>

namespace emilpro
{
	class InstructionFactory : public ArchitectureFactory::IArchitectureListener
	{
	public:
		InstructionFactory();

		void destroy();

		static InstructionFactory &instance();

		IInstruction *create(uint64_t address, std::vector<std::string> encodingVector,
				std::string &encoding, uint8_t *data, size_t size);

		virtual void onArchitectureDetected(ArchitectureFactory::Architecture_t arch);

	private:
	};
}
