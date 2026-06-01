#pragma once
// Bitcoin merkle trees: full root, plus the Stratum branch shortcut that re-roots
// cheaply when only the coinbase txid changes. Hashes in internal byte order.
#include <vector>

#include "util/sha256.hpp"

namespace erikslund::util {

// sha256d(a || b) -- one internal merkle node.
Hash256 hash_pair(const Hash256& a, const Hash256& b);

// Full root (odd rows duplicate the last hash). Empty list -> all-zero hash.
Hash256 merkle_root(std::vector<Hash256> leaves);

// Branch for the index-0 (coinbase) leaf, given the other leaves.
std::vector<Hash256> merkle_branch(const std::vector<Hash256>& other_leaves);

Hash256 merkle_root_from_branch(const Hash256& coinbase, const std::vector<Hash256>& branch);

} // namespace erikslund::util
