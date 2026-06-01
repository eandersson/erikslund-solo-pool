#include "util/url.hpp"

namespace erikslund::util {

std::string redact_url(const std::string& url) {
    const auto scheme_end = url.find("://");
    const size_t authority = scheme_end == std::string::npos ? 0 : scheme_end + 3;
    const size_t authority_end = url.find_first_of("/?#", authority);
    const size_t span =
        authority_end == std::string::npos ? std::string::npos : authority_end - authority;
    const auto at_rel = url.substr(authority, span).rfind('@');
    if (at_rel == std::string::npos)
        return url; // no userinfo
    return url.substr(0, authority) + url.substr(authority + at_rel + 1);
}

} // namespace erikslund::util
