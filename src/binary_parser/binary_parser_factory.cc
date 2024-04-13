#include "emilpro/i_binary_parser.hh"

#include "elf_binary_parser.hh"
// And later the Mach-O parser

using namespace emilpro;

std::unique_ptr<IBinaryParser> IBinaryParser::FromFile(std::string_view path)
{
    auto out = std::make_unique<BfdBinaryParser>(path);

    if (!out->Parse())
    {
        return nullptr;
    }

    return out;
}
