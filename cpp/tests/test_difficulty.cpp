#include <doctest/doctest.h>

#include <string>

#include "util/difficulty.hpp"
#include "util/uint256.hpp"

using namespace erikslund;
using namespace erikslund::util;

TEST_CASE("difficulty-1 compact target") {
    const auto target = target_from_compact(0x1d00ffff);
    CHECK(target.to_display_hex() ==
          "00000000ffff0000000000000000000000000000000000000000000000000000");
    CHECK(difficulty_from_compact(0x1d00ffff) == doctest::Approx(1.0));
}

TEST_CASE("known difficulty from historic nBits") {
    // 0x1b0404cb -> 16307.420938523983 (classic Bitcoin wiki example).
    CHECK(difficulty_from_compact(0x1b0404cb) == doctest::Approx(16307.420938523983));
}

TEST_CASE("target_from_difficulty inverts difficulty_from_target") {
    for (double d : {0.5, 1.0, 512.0, 1000.0, 1'000'000.0, 1e9}) {
        const auto target = target_from_difficulty(d);
        CHECK(difficulty_from_target(target) == doctest::Approx(d).epsilon(0.0001));
    }
}

TEST_CASE("meets_target") {
    const auto target = target_from_compact(0x1d00ffff);

    // The genesis block hash satisfies the genesis target.
    const auto genesis = uint256::from_display_hex(
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
    CHECK(meets_target(genesis, target));

    // The maximum hash does not.
    const auto max_hash = uint256::from_display_hex(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    CHECK_FALSE(meets_target(max_hash, target));

    // A target is trivially <= itself.
    CHECK(meets_target(target, target));
}

TEST_CASE("target_from_compact drops the sign bit (positive targets only)") {
    // Bit 0x00800000 of the mantissa is the sign bit and must be ignored, so
    // 0x1d80ffff yields the same target as 0x1d00ffff.
    CHECK(target_from_compact(0x1d80ffff).to_display_hex() ==
          target_from_compact(0x1d00ffff).to_display_hex());
}

TEST_CASE("target_from_compact small exponent (<= 3) right-shifts the mantissa") {
    // exponent 3: mantissa lands directly in the low three bytes.
    CHECK(target_from_compact(0x03123456).to_display_hex() ==
          "0000000000000000000000000000000000000000000000000000000000123456");
    // exponent 1: only the top mantissa byte survives the >> 16.
    CHECK(target_from_compact(0x01120000).to_display_hex() ==
          "0000000000000000000000000000000000000000000000000000000000000012");
    // exponent 2: top two mantissa bytes survive the >> 8.
    CHECK(target_from_compact(0x02123400).to_display_hex() ==
          "0000000000000000000000000000000000000000000000000000000000001234");
}

TEST_CASE("regtest-easy nBits 0x207fffff is a near-maximum target") {
    const auto target = target_from_compact(0x207fffff);
    // exponent 0x20 = 32, index 29: the mantissa fills the top bytes -> huge target.
    CHECK(target.to_display_hex() ==
          "7fffff0000000000000000000000000000000000000000000000000000000000");
    // Difficulty is well below 1 (target far above the diff-1 target).
    CHECK(difficulty_from_compact(0x207fffff) < 1.0);
}

TEST_CASE("difficulty_from_target of the zero target is zero (no divide-by-zero)") {
    CHECK(difficulty_from_target(uint256{}) == doctest::Approx(0.0));
}

TEST_CASE("target_from_difficulty(0) yields the all-ones (max) target") {
    CHECK(target_from_difficulty(0.0).to_display_hex() == std::string(64, 'f'));
}

TEST_CASE("difficulty doubles as the target halves") {
    // diff 2 corresponds to half the diff-1 target.
    const double d1 = difficulty_from_target(target_from_difficulty(1.0));
    const double d2 = difficulty_from_target(target_from_difficulty(2.0));
    CHECK(d2 == doctest::Approx(2.0 * d1).epsilon(0.0001));
}

TEST_CASE("format_difficulty renders plain decimal, never scientific") {
    CHECK(format_difficulty(1.0) == "1");
    CHECK(format_difficulty(20000.0) == "20000");
    CHECK(format_difficulty(1000000.0) == "1000000");
    // A non-integer >= 1 keeps up to two decimals, trailing zeros trimmed.
    CHECK(format_difficulty(1.5) == "1.5");
    CHECK(format_difficulty(1.25) == "1.25");
    CHECK(format_difficulty(2.0) == "2");
    // Sub-1 difficulty uses 4 significant digits (still decimal, not 2e+04).
    CHECK(format_difficulty(0.5) == "0.5");
    CHECK(format_difficulty(0.001) == "0.001");
    // No scientific notation ever appears.
    CHECK(format_difficulty(123456789.0).find('e') == std::string::npos);
    CHECK(format_difficulty(0.0001).find('e') == std::string::npos);
}
