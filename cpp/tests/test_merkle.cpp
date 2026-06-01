#include <doctest/doctest.h>

#include <vector>

#include "util/bytes.hpp"
#include "util/hex.hpp"
#include "util/merkle.hpp"
#include "util/sha256.hpp"

using namespace erikslund;
using namespace erikslund::util;

namespace {
Hash256 leaf(uint8_t n) {
    // Deterministic distinct leaves for structural tests.
    Bytes b(32, n);
    Hash256 h{};
    for (size_t i = 0; i < 32; ++i)
        h[i] = b[i];
    return h;
}
} // namespace

TEST_CASE("single leaf is its own root") {
    CHECK(merkle_root({leaf(1)}) == leaf(1));
}

TEST_CASE("two leaves hash together") {
    CHECK(merkle_root({leaf(1), leaf(2)}) == hash_pair(leaf(1), leaf(2)));
}

TEST_CASE("odd rows duplicate the last leaf") {
    // root of [a,b,c] == hash(hash(a,b), hash(c,c)).
    const auto expect = hash_pair(hash_pair(leaf(1), leaf(2)), hash_pair(leaf(3), leaf(3)));
    CHECK(merkle_root({leaf(1), leaf(2), leaf(3)}) == expect);
}

TEST_CASE("branch folds back to the full root for any tx count") {
    for (size_t n = 0; n <= 9; ++n) {
        std::vector<Hash256> others;
        for (size_t i = 0; i < n; ++i)
            others.push_back(leaf(static_cast<uint8_t>(i + 10)));

        const Hash256 coinbase = leaf(99);
        std::vector<Hash256> all;
        all.push_back(coinbase);
        all.insert(all.end(), others.begin(), others.end());

        const auto branch = merkle_branch(others);
        CHECK(merkle_root_from_branch(coinbase, branch) == merkle_root(all));
    }
}

TEST_CASE("hash_pair is sha256d of the concatenation") {
    const Hash256 a = leaf(7);
    const Hash256 b = leaf(8);
    Bytes concatenated;
    concatenated.insert(concatenated.end(), a.begin(), a.end());
    concatenated.insert(concatenated.end(), b.begin(), b.end());
    CHECK(hash_pair(a, b) == sha256d(concatenated));
}

TEST_CASE("hash_pair is order-sensitive") {
    CHECK_FALSE(hash_pair(leaf(1), leaf(2)) == hash_pair(leaf(2), leaf(1)));
}

TEST_CASE("empty leaf set yields the all-zero root") {
    CHECK(merkle_root({}) == Hash256{});
}

TEST_CASE("four leaves form a balanced two-level tree") {
    // root([a,b,c,d]) == hash(hash(a,b), hash(c,d)) -- no duplication needed.
    const auto expect = hash_pair(hash_pair(leaf(1), leaf(2)), hash_pair(leaf(3), leaf(4)));
    CHECK(merkle_root({leaf(1), leaf(2), leaf(3), leaf(4)}) == expect);
}

TEST_CASE("branch length is the tree depth (ceil log2 of leaf count)") {
    // With k other txns there are k+1 leaves; depth = number of collapse rounds.
    auto others = [](size_t k) {
        std::vector<Hash256> v;
        for (size_t i = 0; i < k; ++i)
            v.push_back(Hash256{});
        return v;
    };
    CHECK(merkle_branch(others(0)).empty());       // 1 leaf  -> depth 0
    CHECK(merkle_branch(others(1)).size() == 1);   // 2 leaves -> depth 1
    CHECK(merkle_branch(others(2)).size() == 2);   // 3 leaves -> depth 2
    CHECK(merkle_branch(others(3)).size() == 2);   // 4 leaves -> depth 2
    CHECK(merkle_branch(others(4)).size() == 3);   // 5 leaves -> depth 3
    CHECK(merkle_branch(others(7)).size() == 3);   // 8 leaves -> depth 3
    CHECK(merkle_branch(others(8)).size() == 4);   // 9 leaves -> depth 4
}

TEST_CASE("a single-transaction block has an empty branch and root == coinbase") {
    const Hash256 coinbase = leaf(42);
    const auto branch = merkle_branch({});
    CHECK(branch.empty());
    CHECK(merkle_root_from_branch(coinbase, branch) == coinbase);
}
