#include "stratum/message.hpp"

#include <cstdint>

#include <simdjson.h>

namespace erikslund::stratum {

namespace {

// Reject pathologically nested JSON: guards against stack exhaustion on small thread stacks
// (legit Stratum messages are flat).
constexpr int kMaxJsonDepth = 64;

bool within_depth(std::string_view text) {
    int depth = 0;
    bool in_string = false, escaped = false;
    for (char c : text) {
        if (in_string) {
            if (escaped)
                escaped = false;
            else if (c == '\\')
                escaped = true;
            else if (c == '"')
                in_string = false;
            continue;
        }
        if (c == '"')
            in_string = true;
        else if (c == '{' || c == '[') {
            if (++depth > kMaxJsonDepth)
                return false;
        } else if ((c == '}' || c == ']') && depth > 0) {
            --depth;
        }
    }
    return true;
}

} // namespace

std::optional<Request> parse_request(std::string_view line) {
    if (!within_depth(line))
        return std::nullopt;
    try {
        // Per-thread reusable parser; its DOM is valid only until the next parse(), so copy out
        // everything we keep. parse(ptr,len) reuses the parser's buffer -- no padded_string alloc.
        static thread_local simdjson::dom::parser parser;
        simdjson::dom::element doc = parser.parse(line.data(), line.size());
        if (!doc.is_object())
            return std::nullopt;

        std::string_view method;
        if (doc["method"].get(method))  // missing / not a string -> reject
            return std::nullopt;

        Request request;
        request.method = std::string(method);

        simdjson::dom::element id;
        if (!doc["id"].get(id)) {
            if (int64_t number; !id.get(number))
                request.id = number;
            else if (std::string_view text; !id.get(text))
                request.id = std::string(text);
            // any other id type stays null
        }

        simdjson::dom::array params;
        if (!doc["params"].get(params)) {
            request.params.reserve(params.size());
            for (simdjson::dom::element element : params) {
                std::string_view value;
                request.params.emplace_back(element.get(value) ? std::string() : std::string(value));
            }
        }

        // mining.configure nests an array + an object.
        if (request.method == "mining.configure") {
            simdjson::dom::array extensions;
            if (!doc["params"].at(0).get(extensions))
                for (simdjson::dom::element extension : extensions) {
                    std::string_view name;
                    if (!extension.get(name)) {
                        request.configure_extensions.emplace_back(name);
                        if (name == "version-rolling")
                            request.configure_version_rolling = true;
                    }
                }
            // Distinguish "no mask key" (absent -> no client preference) from "key present but
            // malformed/non-string" (-> disable rolling).
            simdjson::dom::element mask_field;
            if (!doc["params"].at(1)["version-rolling.mask"].get(mask_field)) {
                request.version_rolling_mask_present = true;
                std::string_view mask;
                if (!mask_field.get(mask))
                    request.version_rolling_mask = std::string(mask);
            }
        }

        if (request.method == "mining.suggest_difficulty") {
            simdjson::dom::element first;
            if (!doc["params"].at(0).get(first)) {
                double number;
                uint64_t unsigned_integer;
                int64_t integer;
                std::string_view text;
                if (!first.get(number))
                    request.suggested_difficulty = number;
                else if (!first.get(unsigned_integer))
                    request.suggested_difficulty = static_cast<double>(unsigned_integer);
                else if (!first.get(integer))
                    request.suggested_difficulty = static_cast<double>(integer);
                else if (!first.get(text)) {
                    try {
                        request.suggested_difficulty = std::stod(std::string(text));
                    } catch (const std::exception&) {  // NOLINT(bugprone-empty-catch): deliberate
                        // non-numeric string: leave unset (acked but ignored downstream)
                    }
                }
            }
        }
        return request;
    } catch (const simdjson::simdjson_error&) {
        return std::nullopt;
    }
}

json make_result(const json& id, json result) {
    return json{{"id", id}, {"result", std::move(result)}, {"error", nullptr}};
}

json make_error(const json& id, const StratumError& error) {
    return json{{"id", id},
                {"result", nullptr},
                {"error", json::array({error.code, std::string(error.message), nullptr})}};
}

json make_notification(std::string_view method, json params) {
    return json{{"id", nullptr}, {"method", std::string(method)}, {"params", std::move(params)}};
}

std::string make_result_line(const json& id, bool result) {
    std::string out = "{\"error\":null,\"id\":";
    out += id.dump();
    out += result ? ",\"result\":true}" : ",\"result\":false}";
    return out;
}

std::string make_notify_line(const std::string& job_id, const std::string& prevhash_stratum,
                             const std::string& coinbase1_hex, const std::string& coinbase2_hex,
                             const std::vector<std::string>& merkle_branch_hex,
                             const std::string& version_hex, const std::string& nbits_hex,
                             const std::string& ntime_hex, bool clean) {
    // Wire shape (nlohmann's lexicographic key order):
    // {"id":null,"method":"mining.notify","params":["<job>","<prev>","<cb1>","<cb2>",
    //  ["<branch>",...],"<version>","<nbits>","<ntime>",<clean>]}
    size_t branches_size = 2; // "[]"
    for (const auto& branch : merkle_branch_hex)
        branches_size += branch.size() + 3; // quotes + comma
    std::string out;
    out.reserve(64 + job_id.size() + prevhash_stratum.size() + coinbase1_hex.size() +
                coinbase2_hex.size() + branches_size + version_hex.size() + nbits_hex.size() +
                ntime_hex.size() + 32);
    out += R"({"id":null,"method":"mining.notify","params":[")";
    out += job_id;
    out += "\",\"";
    out += prevhash_stratum;
    out += "\",\"";
    out += coinbase1_hex;
    out += "\",\"";
    out += coinbase2_hex;
    out += "\",[";
    bool first = true;
    for (const auto& branch : merkle_branch_hex) {
        if (!first)
            out += ',';
        first = false;
        out += '"';
        out += branch;
        out += '"';
    }
    out += "],\"";
    out += version_hex;
    out += "\",\"";
    out += nbits_hex;
    out += "\",\"";
    out += ntime_hex;
    out += clean ? "\",true]}" : "\",false]}";
    return out;
}

std::string make_error_line(const json& id, const StratumError& error) {
    // error.message is a compile-time constant with no JSON-special chars; embed without escaping.
    std::string out = "{\"error\":[";
    out += std::to_string(error.code);
    out += ",\"";
    out += error.message;
    out += "\",null],\"id\":";
    out += id.dump();
    out += ",\"result\":null}";
    return out;
}

} // namespace erikslund::stratum
