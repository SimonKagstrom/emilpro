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
    ForAllSections(std::function<void(std::unique_ptr<emilpro::ISection>)> on_section) = 0;

    virtual Machine GetMachine() const = 0;

    static std::unique_ptr<IBinaryParser> FromFile(std::string_view path);
};

} // namespace emilpro
