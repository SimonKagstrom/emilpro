#include "emilpro/i_section.hh"

#include <vector>

using namespace emilpro;

namespace
{

class Section : public ISection
{
public:
    Section(std::span<const std::byte> data, uint64_t start_address, Type type)
        : m_data(data.begin(), data.end())
        , m_start_address(start_address)
        , m_type(type)
    {
    }

private:
    std::span<const std::byte> Data() const final
    {
        return m_data;
    }

    uint64_t StartAddress() const final
    {
        return m_start_address;
    }

    size_t Size() const final
    {
        return m_data.size();
    }

    const std::vector<std::byte> m_data;
    const uint64_t m_start_address;
    const Type m_type;
};

} // namespace

std::unique_ptr<ISection>
ISection::Create(std::span<const std::byte> data, uint64_t start_address, Type type)
{
    return std::make_unique<Section>(data, start_address, type);
}
