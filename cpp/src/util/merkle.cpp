#include "util/merkle.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include <crypto/sha256.h> // SHA256D64: batched double-SHA of 64-byte blobs

#include "util/bytes.hpp"

namespace erikslund::util {

Hash256 hash_pair(const Hash256& a, const Hash256& b) {
    // a||b is the 64-byte blob the fused SHA256D64 kernel consumes; keep it on the stack.
    uint8_t buffer[64];
    std::memcpy(buffer, a.data(), 32);
    std::memcpy(buffer + 32, b.data(), 32);
    Hash256 out;
    SHA256D64(out.data(), buffer, 1);
    return out;
}

namespace {

// out[i] = sha256d(in[2i] || in[2i+1]). The contiguous Hash256 array is the pairs*64-byte layout
// SHA256D64 consumes, so it runs the batched kernels. Requires even level.size().
std::vector<Hash256> collapse_level(const std::vector<Hash256>& level) {
    const size_t pairs = level.size() / 2;
    std::vector<Hash256> next(pairs);
    if (pairs > 0)
        SHA256D64(next[0].data(), level[0].data(), pairs);
    return next;
}

} // namespace

Hash256 merkle_root(std::vector<Hash256> leaves) {
    if (leaves.empty())
        return Hash256{};
    while (leaves.size() > 1) {
        if (leaves.size() % 2 != 0)
            leaves.push_back(leaves.back()); // duplicate odd tail
        leaves = collapse_level(leaves);
    }
    return leaves.front();
}

std::vector<Hash256> merkle_branch(const std::vector<Hash256>& other_leaves) {
    std::vector<Hash256> branch;

    // Zero placeholder at index 0: the coinbase is on the path at every level, so its value
    // never enters a branch element (we only collect the sibling, [1]).
    std::vector<Hash256> level;
    level.reserve(other_leaves.size() + 1);
    level.push_back(Hash256{});
    level.insert(level.end(), other_leaves.begin(), other_leaves.end());

    while (level.size() > 1) {
        if (level.size() % 2 != 0)
            level.push_back(level.back());
        branch.push_back(level[1]);
        level = collapse_level(level);
    }
    return branch;
}

Hash256 merkle_root_from_branch(const Hash256& coinbase, const std::vector<Hash256>& branch) {
    Hash256 current = coinbase;
    for (const Hash256& sibling : branch)
        current = hash_pair(current, sibling);
    return current;
}

} // namespace erikslund::util
