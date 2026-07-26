#pragma once

#include <dbgeng.h>

#include <string>
#include <string_view>

namespace wef {

class Output {
public:
    explicit Output(IDebugControl* control);

    void normal(std::string_view text) const;
    void warning(std::string_view text) const;
    void error(std::string_view text) const;
    void line(std::string_view text) const;
    void blank() const;
    void dmlLine(std::string_view plain, std::string_view dml) const;
    void heading(std::string_view text) const;
    void field(std::string_view label, std::string_view value) const;

private:
    void write(ULONG mask, std::string_view text) const;
    bool writeDml(ULONG mask, std::string_view text) const;

    IDebugControl* control_;
};

bool outputUseDml();
void setOutputUseDml(bool enabled);
std::string dmlEscape(std::string_view text);
std::string dmlCommandLink(std::string_view label, std::string_view command);

}
