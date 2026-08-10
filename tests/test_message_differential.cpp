// Differential fuzz for the request parser: parse_request()'s typed fast path and the
// authoritative DOM path (detail::parse_request_dom) must agree on EVERY input, not just the
// hand-written matrix in test_message.cpp. A fixed-seed xorshift PRNG mutates a corpus of
// realistic Stratum lines (byte flips, inserts, deletes, cross-splices, truncation) and asserts
// field-level agreement plus byte-identical response id echoes on every mutant. Deterministic:
// a failure reproduces exactly. Runs in the plain suite and under the ASan/UBSan and TSan gates.
#include <doctest/doctest.h>

#include <cstdint>
#include <string>
#include <vector>

#include "stratum/message.hpp"

using namespace erikslund::stratum;

namespace {

// Mirror of parse_request's depth gate (kMaxJsonDepth = 64). parse_request rejects over-deep
// lines before either parse path runs; the DOM path exposed for testing has no gate, so the
// comparison below must apply the same pre-filter. Deliberately duplicated: if the production
// gate's semantics drift from this copy, the over-depth assertion in the loop catches it.
bool within_depth_copy(std::string_view text) {
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
            if (++depth > 64)
                return false;
        } else if ((c == '}' || c == ']') && depth > 0) {
            --depth;
        }
    }
    return true;
}

struct XorShift64 {
    uint64_t state;
    uint64_t next() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        return state;
    }
    // Bounded draw; bound must be > 0.
    size_t below(size_t bound) { return static_cast<size_t>(next() % bound); }
};

// Characters that matter to a JSON parser, over-weighted vs. plain noise so mutations hit
// structure, not just string contents.
constexpr char kStructural[] = "{}[]\",:.0123456789eE+-\\tfnu ";

void mutate(std::string& line, XorShift64& rng, const std::vector<std::string>& corpus) {
    const int ops = 1 + static_cast<int>(rng.below(4));
    for (int op = 0; op < ops; ++op) {
        if (line.empty())
            line = corpus[rng.below(corpus.size())];
        switch (rng.below(5)) {
        case 0: // flip one byte to a structural char (or, rarely, an arbitrary byte)
            line[rng.below(line.size())] =
                rng.below(8) == 0 ? static_cast<char>(rng.next() & 0xff)
                                  : kStructural[rng.below(sizeof(kStructural) - 1)];
            break;
        case 1: // insert a structural char
            line.insert(line.begin() + static_cast<std::ptrdiff_t>(rng.below(line.size() + 1)),
                        kStructural[rng.below(sizeof(kStructural) - 1)]);
            break;
        case 2: // delete a byte
            line.erase(rng.below(line.size()), 1);
            break;
        case 3: { // splice a random slice of another corpus line into a random position
            const std::string& donor = corpus[rng.below(corpus.size())];
            const size_t from = rng.below(donor.size());
            const size_t len = 1 + rng.below(donor.size() - from);
            line.insert(rng.below(line.size() + 1), donor, from, len);
            break;
        }
        case 4: // truncate the tail
            line.resize(rng.below(line.size() + 1));
            break;
        }
    }
}

void check_agreement(const std::string& line) {
    CAPTURE(line);
    const auto fast = parse_request(line);
    if (!within_depth_copy(line)) {
        // Over-deep input: parse_request must reject it outright (gate runs before any parse).
        CHECK_FALSE(fast.has_value());
        return;
    }
    const auto dom = detail::parse_request_dom(line);
    REQUIRE(fast.has_value() == dom.has_value());
    if (!fast)
        return;
    CHECK(fast->method == dom->method);
    CHECK(fast->params == dom->params);
    CHECK(make_result_line(fast->id, true) == make_result_line(dom->id, true));
    CHECK(make_error_line(fast->id, ERR_OTHER) == make_error_line(dom->id, ERR_OTHER));
    CHECK(fast->configure_extensions == dom->configure_extensions);
    CHECK(fast->configure_version_rolling == dom->configure_version_rolling);
    CHECK(fast->version_rolling_mask_present == dom->version_rolling_mask_present);
    CHECK(fast->version_rolling_mask == dom->version_rolling_mask);
    CHECK(fast->suggested_difficulty == dom->suggested_difficulty);
}

} // namespace

TEST_CASE("differential fuzz: typed fast path agrees with the DOM parse on mutated inputs") {
    const std::vector<std::string> corpus = {
        R"({"id":1,"method":"mining.submit","params":["addr.w","ab12cd34","0001","6553f100","2a2a2a2a"]})",
        R"({"id":1,"method":"mining.submit","params":["addr","ab12cd34","0001","6553f100","2a2a2a2a","1fffe000"]})",
        R"({"id":"c-1","method":"mining.subscribe","params":["agent/1.0"]})",
        R"({"id":2,"method":"mining.authorize","params":["addr.worker","x"]})",
        R"({"id":3,"method":"mining.configure","params":[["version-rolling"],{"version-rolling.mask":"1fffe000"}]})",
        R"({"id":9,"method":"mining.suggest_difficulty","params":[12.5]})",
        R"({"id":null,"method":"mining.extranonce.subscribe","params":[]})",
        R"({"jsonrpc":"2.0","id":9007199254740992,"method":"mining.submit","params":[]})",
        R"({"method":"mining.submit","params":["w",null,3,{"a":[1,2]},true]})",
        R"([{"method":"x"},"not an object",42])",
    };

    // Every corpus line agrees unmutated (sanity anchor for the loop below).
    for (const std::string& line : corpus)
        check_agreement(line);

    XorShift64 rng{0x6572696b736c756eULL}; // fixed seed: failures reproduce exactly
    for (int iteration = 0; iteration < 20000; ++iteration) {
        std::string line = corpus[rng.below(corpus.size())];
        mutate(line, rng, corpus);
        check_agreement(line);
    }
}
