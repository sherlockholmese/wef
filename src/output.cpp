#include "output.hpp"

#include <atomic>
#include <string>

namespace wef {

namespace {

std::atomic_bool g_useDml = true;

std::string color(std::string_view value, std::string_view fg) {
    return "<col fg=\"" + std::string(fg) + "\">" + dmlEscape(value) + "</col>";
}

}

Output::Output(IDebugControl* control) : control_(control) {}

void Output::normal(std::string_view text) const {
    write(DEBUG_OUTPUT_NORMAL, text);
}

void Output::warning(std::string_view text) const {
    if (outputUseDml() &&
        writeDml(DEBUG_OUTPUT_WARNING, color("warning: ", "yellow") + dmlEscape(text))) {
        return;
    }
    write(DEBUG_OUTPUT_WARNING, "warning: ");
    write(DEBUG_OUTPUT_WARNING, text);
}

void Output::error(std::string_view text) const {
    if (outputUseDml() &&
        writeDml(DEBUG_OUTPUT_ERROR, color("error: ", "red") + dmlEscape(text))) {
        return;
    }
    write(DEBUG_OUTPUT_ERROR, "error: ");
    write(DEBUG_OUTPUT_ERROR, text);
}

void Output::line(std::string_view text) const {
    write(DEBUG_OUTPUT_NORMAL, text);
    write(DEBUG_OUTPUT_NORMAL, "\n");
}

void Output::blank() const {
    write(DEBUG_OUTPUT_NORMAL, "\n");
}

void Output::dmlLine(std::string_view plain, std::string_view dml) const {
    if (outputUseDml() &&
        writeDml(DEBUG_OUTPUT_NORMAL, std::string(dml) + "\n")) {
        return;
    }
    line(plain);
}

void Output::heading(std::string_view text) const {
    const std::string plain = "== " + std::string(text) + " ==";
    dmlLine(plain, color(plain, "cyan"));
}

void Output::field(std::string_view label, std::string_view value) const {
    const std::string plain = "  " + std::string(label) + ": " + std::string(value);
    const std::string dml = "  " + color(label, "green") + ": " + color(value, "white");
    dmlLine(plain, dml);
}

void Output::write(ULONG mask, std::string_view text) const {
    if (control_ == nullptr || text.empty()) {
        return;
    }

    const std::string copy(text);
    control_->Output(mask, "%s", copy.c_str());
}

bool Output::writeDml(ULONG mask, std::string_view text) const {
    if (control_ == nullptr || text.empty()) {
        return false;
    }

    const std::string copy(text);
    return SUCCEEDED(control_->ControlledOutput(
        DEBUG_OUTCTL_THIS_CLIENT | DEBUG_OUTCTL_DML,
        mask,
        "%s",
        copy.c_str()));
}

bool outputUseDml() {
    return g_useDml.load();
}

void setOutputUseDml(bool enabled) {
    g_useDml.store(enabled);
}

std::string dmlEscape(std::string_view text) {
    std::string escaped;
    escaped.reserve(text.size());
    for (const char ch : text) {
        switch (ch) {
        case '&':
            escaped += "&amp;";
            break;
        case '<':
            escaped += "&lt;";
            break;
        case '>':
            escaped += "&gt;";
            break;
        case '"':
            escaped += "&quot;";
            break;
        default:
            escaped.push_back(ch);
            break;
        }
    }
    return escaped;
}

std::string dmlCommandLink(std::string_view label, std::string_view command) {
    return "<link cmd=\"" + dmlEscape(command) + "\">[" + dmlEscape(label) + "]</link>";
}

}
