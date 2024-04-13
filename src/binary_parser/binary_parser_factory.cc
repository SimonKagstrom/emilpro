#include "emilpro/i_binary_parser.hh"

#include "bfd_binary_parser.hh"

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
