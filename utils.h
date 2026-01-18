#pragma once

#include <algorithm>
#include <string>
#include <regex>

namespace libtouchstone {

// Check if a container contains a value.
template<typename Container, typename T>
inline bool contains(const Container& container, const T& value) {
    return std::find(container.begin(), container.end(), value) != container.end();
}

// String-specific overload for substring search.
inline bool contains(const std::string& str, const char* substr) {
    return str.find(substr) != std::string::npos;
}

// Extract a group from a regex match.
inline std::string regex_extract(const std::string& str, const std::string& pattern, int group = 1) {
    std::regex re(pattern);
    std::smatch match;
    if (std::regex_search(str, match, re) && (int)match.size() > group) return match[group].str();
    return "";
}

}  // namespace libtouchstone
