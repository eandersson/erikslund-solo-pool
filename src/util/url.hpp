#pragma once
// URL hygiene for logs and the API.
#include <string>

namespace erikslund::util {

// Strip "user:pass@" userinfo so RPC credentials can't leak via the API or logs. Cuts at the LAST
// '@' in the authority (passwords may contain '@'); also handles scheme-less URLs. No-op if absent.
std::string redact_url(const std::string& url);

} // namespace erikslund::util
