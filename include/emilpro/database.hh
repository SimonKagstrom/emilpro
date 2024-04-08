#include "i_binary_parser.hh"
#include "i_disassembler.hh"

namespace emilpro
{

class Database
{
public:
    Database(std::unique_ptr<IBinaryParser> parser, std::unique_ptr<IDisassembler> disassembler);
};

} // namespace emilpro
