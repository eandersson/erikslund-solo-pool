#include "stratum/job.hpp"

#include <format>
#include <stdexcept>
#include <utility>
#include <vector>

#include "bitcoin/coinbase.hpp"
#include "util/difficulty.hpp"
#include "util/endian.hpp"
#include "util/hex.hpp"
#include "util/merkle.hpp"
#include "util/varint.hpp"

namespace erikslund::stratum {

namespace {

constexpr int64_t kNtimeSlack = 7200;
constexpr int64_t kNtimeSubmitMargin = 120;

ShareResult rejected(ShareReject reject) {
    ShareResult result;
    result.valid = false;
    result.reject = reject;
    return result;
}

// Display hex -> mining.notify form: internal hash with each 4-byte word byte-reversed.
std::string prevhash_to_stratum(const std::string& display_hex) {
    const Bytes internal = util::reversed(util::from_hex(display_hex));
    if (internal.size() != 32)
        throw std::invalid_argument("previousblockhash is not 32 bytes");
    Bytes out;
    out.reserve(32);
    for (size_t word = 0; word < 32; word += 4)
        for (int byte = 3; byte >= 0; --byte)
            out.push_back(internal[word + static_cast<size_t>(byte)]);
    return util::to_hex(out);
}

} // namespace

std::string_view reject_reason(ShareReject reject) {
    switch (reject) {
    case ShareReject::None: return "ok";
    case ShareReject::InvalidExtranonce2Size: return "invalid extranonce2 size";
    case ShareReject::MalformedField: return "malformed share field";
    case ShareReject::NtimeOutOfRange: return "ntime out of range";
    case ShareReject::MalformedVersionBits: return "malformed version bits";
    case ShareReject::VersionRollingNotNegotiated: return "version rolling not negotiated";
    case ShareReject::VersionBitsOutsideMask: return "version bits outside negotiated mask";
    case ShareReject::AboveTarget: return "above target";
    }
    return "unknown";
}

Job::Job(std::string job_id, bitcoin::BlockTemplate block_template, ByteView tag,
         size_t extranonce1_size, size_t extranonce2_size, uint32_t coinbase_version, bool clean,
         ByteView donation_script, double donation_percent)
    : job_id_(std::move(job_id)),
      clean_(clean),
      height_(block_template.height),
      version_(block_template.version),
      curtime_(block_template.curtime),
      bits_(block_template.bits),
      coinbase_value_(block_template.coinbase_value),
      network_target_(util::target_from_compact(block_template.bits)),
      prevhash_internal_(util::reversed(util::from_hex(block_template.previousblockhash))),
      prevhash_stratum_(prevhash_to_stratum(block_template.previousblockhash)),
      witness_commitment_(std::move(block_template.witness_commitment)),
      has_witness_(witness_commitment_.has_value()),
      tag_(tag.begin(), tag.end()),
      extranonce2_size_(extranonce2_size),
      txn_count_(block_template.txn_count),
      // Steal the concatenated tx blob (multi-MB on mainnet) -- the point of taking by value.
      txn_data_(std::move(block_template.txn_data)),
      nbits_hex_(std::move(block_template.bits_hex)) {
    donation_script_.assign(donation_script.begin(), donation_script.end());
    donation_percent_ = donation_percent;

    merkle_branch_ = util::merkle_branch(block_template.txids_internal);
    merkle_branch_hex_.reserve(merkle_branch_.size());
    for (const auto& node : merkle_branch_)
        merkle_branch_hex_.push_back(util::to_hex(node));

    coinbase1_ = bitcoin::build_coinbase1(height_, extranonce1_size + extranonce2_size, tag, coinbase_version);
    coinbase1_hex_ = util::to_hex(coinbase1_);
    version_hex_ = std::format("{:08x}", version_);
    ntime_hex_ = std::format("{:08x}", curtime_);
}

Bytes Job::build_coinbase2(ByteView payout_script) const {
    std::vector<bitcoin::CoinbaseOutput> outputs;
    if (donation_percent_ > 0.0 && !donation_script_.empty()) {
        const uint64_t donation_amount = static_cast<uint64_t>(
            static_cast<double>(coinbase_value_) * donation_percent_ / 100.0);
        outputs.push_back(
            {coinbase_value_ - donation_amount, Bytes(payout_script.begin(), payout_script.end())});
        outputs.push_back({donation_amount, donation_script_});
    } else {
        outputs.push_back({coinbase_value_, Bytes(payout_script.begin(), payout_script.end())});
    }
    return bitcoin::build_coinbase2(outputs, witness_commitment_, tag_);
}

double Job::network_difficulty() const {
    return util::difficulty_from_target(network_target_);
}

bool Job::mines_on(const std::string& tip_display_hex) const {
    try {
        return util::reversed(util::from_hex(tip_display_hex)) == prevhash_internal_;
    } catch (const std::invalid_argument&) {
        return false; // malformed hex can't be our parent
    }
}

std::string Job::work_signature() const {
    // Every field a miner hashes plus the coinbase_value + witness commitment that drive coinbase2.
    std::string sig = prevhash_stratum_;
    sig += '|' + version_hex_;
    sig += '|' + nbits_hex_;
    sig += '|' + ntime_hex_;
    sig += '|' + coinbase1_hex_;
    sig += '|' + std::to_string(coinbase_value_);
    if (witness_commitment_)
        sig += '|' + util::to_hex(*witness_commitment_);
    for (const auto& branch : merkle_branch_hex_)
        sig += '|' + branch;
    return sig;
}

Bytes Job::build_header(const util::Hash256& merkle_root, uint32_t ntime, uint32_t nonce,
                        uint32_t version) const {
    Bytes header;
    header.reserve(80);
    util::append_le32(header, version);
    append(header, prevhash_internal_);
    append(header, merkle_root);
    util::append_le32(header, ntime);
    util::append_le32(header, bits_);
    util::append_le32(header, nonce);
    return header;
}

ShareResult Job::validate_share(const ShareInput& input) const {
    // Cheap length gate before hex-decode (an oversized extranonce2 always rejects).
    if (input.extranonce2_hex.size() > extranonce2_size_ * 2) [[unlikely]]
        return rejected(ShareReject::InvalidExtranonce2Size);

    Bytes extranonce2;
    uint32_t ntime = 0;
    uint32_t nonce = 0;
    try {
        extranonce2 = util::from_hex(input.extranonce2_hex);
        ntime = util::parse_hex_u32(input.ntime_hex);
        nonce = util::parse_hex_u32(input.nonce_hex);
    } catch (const std::invalid_argument&) {
        return rejected(ShareReject::MalformedField);
    }

    if (extranonce2.size() != extranonce2_size_) [[unlikely]]
        return rejected(ShareReject::InvalidExtranonce2Size);

    const int64_t ntime_min = static_cast<int64_t>(curtime_);
    const int64_t ntime_max = input.now_unix + kNtimeSlack - kNtimeSubmitMargin;
    if (static_cast<int64_t>(ntime) < ntime_min || static_cast<int64_t>(ntime) > ntime_max) [[unlikely]]
        return rejected(ShareReject::NtimeOutOfRange);

    uint32_t version = version_;
    if (input.version_bits_hex) {
        uint32_t rolled = 0;
        try {
            rolled = util::parse_hex_u32(*input.version_bits_hex);
        } catch (const std::invalid_argument&) {
            return rejected(ShareReject::MalformedVersionBits);
        }
        if (input.version_mask == 0) {
            if (rolled != 0) [[unlikely]]
                return rejected(ShareReject::VersionRollingNotNegotiated);
        } else if (rolled & ~input.version_mask) [[unlikely]] {
            return rejected(ShareReject::VersionBitsOutsideMask);
        } else {
            version = (version_ & ~input.version_mask) | (rolled & input.version_mask);
        }
    }

    Bytes coinbase;
    coinbase.reserve(coinbase1_.size() + input.extranonce1.size() + extranonce2.size() +
                     input.coinbase2.size());
    append(coinbase, coinbase1_);
    append(coinbase, input.extranonce1);
    append(coinbase, extranonce2);
    append(coinbase, input.coinbase2);

    const util::Hash256 coinbase_txid = util::sha256d(coinbase);
    const util::Hash256 root = util::merkle_root_from_branch(coinbase_txid, merkle_branch_);
    Bytes header = build_header(root, ntime, nonce, version);
    const util::Hash256 block_hash = util::sha256d(header);
    const util::uint256 hash_value = util::uint256::from_le_bytes(block_hash);

    const double difficulty = util::difficulty_from_target(hash_value);
    const bool is_block = util::meets_target(hash_value, network_target_);

    if (!is_block && !util::meets_target(hash_value, input.share_target)) {
        ShareResult result;
        result.valid = false;
        result.reject = ShareReject::AboveTarget;
        result.difficulty = difficulty;
        return result;
    }

    ShareResult result;
    result.valid = true;
    result.difficulty = difficulty;
    result.is_block = is_block;
    result.block_hash_hex = util::to_hex(util::reversed(block_hash));
    result.header = std::move(header);
    result.legacy_coinbase = std::move(coinbase);
    return result;
}

std::string Job::build_block_hex(ByteView legacy_coinbase, ByteView header) const {
    const Bytes coinbase = has_witness_
                               ? bitcoin::legacy_to_witness(legacy_coinbase)
                               : Bytes(legacy_coinbase.begin(), legacy_coinbase.end());
    Bytes block;
    append(block, header);
    append(block, util::encode_varint(txn_count_ + 1));
    append(block, coinbase);
    append(block, txn_data_);
    return util::to_hex(block);
}

} // namespace erikslund::stratum
