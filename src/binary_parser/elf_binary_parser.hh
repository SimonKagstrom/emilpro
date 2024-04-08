#include "emilpro/i_binary_parser.hh"

namespace emilpro
{

class ElfBinaryParser : public IBinaryParser
{
public:
    explicit ElfBinaryParser(std::string_view path);
    ~ElfBinaryParser() override = default;

    bool Parse();

private:
    Machine GetMachine() const final;
    void ForAllSections(std::function<void(std::unique_ptr<ISection>)> on_section) final;


    std::string m_path;
    Machine m_machine {Machine::kUnknown};
};

} // namespace emilpro
