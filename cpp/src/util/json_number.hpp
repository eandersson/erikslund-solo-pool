#pragma once
// Render a double for C++/Python byte-parity.
#include <string>

#include <glaze/glaze.hpp>

namespace erikslund::util {

inline std::string format_json_number(double value) {
    std::string s = glz::write_json(value).value_or("0");
    bool has_point = false;
    bool has_exp = false;
    for (char& c : s) {
        if (c == 'E') {
            c = 'e';
            has_exp = true;
        } else if (c == 'e') {
            has_exp = true;
        } else if (c == '.') {
            has_point = true;
        }
    }
    if (!has_point && !has_exp)
        s += ".0";
    return s;
}

} // namespace erikslund::util
