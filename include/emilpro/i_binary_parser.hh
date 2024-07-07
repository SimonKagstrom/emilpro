#pragma once

#include "i_section.hh"
#include "machine.hh"

#include <functional>
#include <memory>
#include <span>
#include <string_view>

namespace emilpro
{

class IBinaryParser
{
public:
    virtual ~IBinaryParser() = default;

    virtual void
    ForAllSections(const std::function<void(std::unique_ptr<emilpro::ISection>)> &on_section) = 0;

    virtual Machine GetMachine() const = 0;

    static std::unique_ptr<IBinaryParser> FromFile(std::string_view path,
                                                    std::optional<Machine> machine_hint = std::nullopt);
};

} // namespace emilpro
