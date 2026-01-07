#pragma once

#include <string>
#include <regex>

namespace libtouchstone {

inline bool contains(const std::string& str, const char* substr) {
    return str.find(substr) != std::string::npos;
}

inline std::string regex_extract(const std::string& str, const std::string& pattern, int group = 1) {
    std::regex re(pattern);
    std::smatch match;
    if (std::regex_search(str, match, re) && (int)match.size() > group) return match[group].str();
    return "";
}

}  // namespace libtouchstone
