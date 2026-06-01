#pragma once
// One block template as mineable work + share validation. Per-template state is shared;
// coinbase2 (payout) is per miner. Immutable + pure validate_share().
#include <atomic>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "bitcoin/block_template.hpp"
#include "util/bytes.hpp"
#include "util/sha256.hpp"
#include "util/uint256.hpp"

namespace erikslund::stratum {

// Why a share was rejected; reject_reason() maps it to a stable human string for logs.
enum class ShareReject : uint8_t {
    None,
    InvalidExtranonce2Size,
    MalformedField,
    NtimeOutOfRange,
    MalformedVersionBits,
    VersionRollingNotNegotiated,
    VersionBitsOutsideMask,
    AboveTarget,
};

std::string_view reject_reason(ShareReject reject);

struct ShareResult {
    bool valid = false;
    ShareReject reject = ShareReject::None; // why, when !valid
    double difficulty = 0.0;                // pool difficulty this hash satisfies (always set)
    bool is_block = false;                  // hash <= network target
    // Work fields below: populated only for accepted shares; empty on the reject path.
    std::string block_hash_hex; // canonical (display) hash
    Bytes header;
    Bytes legacy_coinbase;
};

struct ShareInput {
    ByteView coinbase2;
    ByteView extranonce1;
    std::string_view extranonce2_hex;
    std::string_view ntime_hex;
    std::string_view nonce_hex;
    util::uint256 share_target;
    std::optional<std::string> version_bits_hex;
    uint32_t version_mask = 0;
    int64_t now_unix = 0;
};

class Job {
public:
    // Takes the template BY VALUE: its multi-MB tx blob is moved out, so callers pass an rvalue.
    Job(std::string job_id, bitcoin::BlockTemplate block_template, ByteView tag,
        size_t extranonce1_size, size_t extranonce2_size, uint32_t coinbase_version,
        bool clean = true, ByteView donation_script = {}, double donation_percent = 0.0);

    // mining.notify fields.
    const std::string& job_id() const { return job_id_; }
    const std::string& prevhash_stratum() const { return prevhash_stratum_; }
    const std::string& coinbase1_hex() const { return coinbase1_hex_; }
    const std::vector<std::string>& merkle_branch_hex() const { return merkle_branch_hex_; }
    const std::string& version_hex() const { return version_hex_; }
    const std::string& nbits_hex() const { return nbits_hex_; }
    const std::string& ntime_hex() const { return ntime_hex_; }
    bool clean() const { return clean_; }
    int64_t height() const { return height_; }
    int txn_count() const { return static_cast<int>(txn_count_); }
    double network_difficulty() const;

    // True if this job mines on top of `tip_display_hex` (display-order hash from bitcoind).
    bool mines_on(const std::string& tip_display_hex) const;

    // Identity of the mining work (ignores job_id/clean): equal signature => identical headers
    // for any extranonce/nonce, so rebroadcasting the second only resets miners.
    std::string work_signature() const;

    Bytes build_coinbase2(ByteView payout_script) const;

    uint64_t publish_seq() const { return publish_seq_.load(std::memory_order_relaxed); }
    void set_publish_seq(uint64_t seq) const { publish_seq_.store(seq, std::memory_order_relaxed); }

    // Pure; every field is treated as untrusted.
    ShareResult validate_share(const ShareInput& input) const;

    std::string build_block_hex(ByteView legacy_coinbase, ByteView header) const;

private:
    Bytes build_header(const util::Hash256& merkle_root, uint32_t ntime, uint32_t nonce,
                       uint32_t version) const;

    std::string job_id_;
    bool clean_;
    int64_t height_;
    uint32_t version_;
    uint32_t curtime_;
    uint32_t bits_;
    uint64_t coinbase_value_;
    util::uint256 network_target_;

    Bytes prevhash_internal_;
    std::string prevhash_stratum_;
    std::optional<Bytes> witness_commitment_;
    bool has_witness_;

    Bytes tag_;
    size_t extranonce2_size_;
    Bytes donation_script_;
    double donation_percent_ = 0.0;

    uint32_t txn_count_;
    Bytes txn_data_;
    std::vector<util::Hash256> merkle_branch_;
    std::vector<std::string> merkle_branch_hex_;

    Bytes coinbase1_;
    std::string coinbase1_hex_;
    std::string version_hex_;
    std::string nbits_hex_;
    std::string ntime_hex_;

    mutable std::atomic<uint64_t> publish_seq_{0}; // see publish_seq()
};

} // namespace erikslund::stratum
