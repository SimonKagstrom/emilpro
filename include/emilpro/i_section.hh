#include <cstdint>
#include <memory>
#include <span>

namespace emilpro
{

class ISection
{
public:
    enum class Type
    {
        kData,
        kInstructions,
        kOther,
    };

    virtual ~ISection() = default;

    virtual std::span<const std::byte> Data() const = 0;

    virtual uint64_t StartAddress() const = 0;

    virtual size_t Size() const = 0;


    static std::unique_ptr<ISection>
    Create(std::span<const std::byte> data, uint64_t start_address, Type type);
};

} // namespace emilpro
