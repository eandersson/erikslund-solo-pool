#include "bitcoin/mining_ipc_client.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>

#include "util/block_header.hpp"
#include "util/endian.hpp"
#include "util/hex.hpp"
#include "util/varint.hpp"

namespace erikslund::bitcoin {

namespace {

constexpr uint64_t kMaxMoney = 2'100'000'000'000'000;

class Cursor {
public:
    explicit Cursor(ByteView bytes) : bytes_(bytes) {}

    uint8_t peek(size_t lookahead = 0) const {
        if (lookahead >= remaining())
            throw std::invalid_argument("IPC serialization is truncated");
        return bytes_[offset_ + lookahead];
    }

    ByteView take(size_t size) {
        if (size > remaining())
            throw std::invalid_argument("IPC serialization is truncated");
        const ByteView result = bytes_.subspan(offset_, size);
        offset_ += size;
        return result;
    }

    void skip(size_t size) { static_cast<void>(take(size)); }

    uint64_t compact_size() {
        const util::Varint decoded = util::decode_varint(bytes_.subspan(offset_));
        if ((decoded.consumed == 3 && decoded.value < 0xfd) ||
            (decoded.consumed == 5 && decoded.value <= 0xffff) ||
            (decoded.consumed == 9 && decoded.value <= 0xffffffff))
            throw std::invalid_argument("IPC serialization contains a non-canonical CompactSize");
        offset_ += decoded.consumed;
        return decoded.value;
    }

    void skip_compact_bytes() {
        const uint64_t size = compact_size();
        if (size > remaining())
            throw std::invalid_argument("IPC serialization contains a truncated byte array");
        skip(static_cast<size_t>(size));
    }

    size_t offset() const { return offset_; }
    size_t remaining() const { return bytes_.size() - offset_; }

private:
    ByteView bytes_;
    size_t offset_ = 0;
};

void skip_transaction(Cursor& cursor) {
    cursor.skip(sizeof(uint32_t)); // nVersion

    bool has_witness = false;
    if (cursor.peek() == 0) {
        const uint8_t flags = cursor.peek(1);
        if (flags != 0) {
            if (flags != 1)
                throw std::invalid_argument("IPC block transaction has unsupported witness flags");
            cursor.skip(2);
            has_witness = true;
        }
    }

    const uint64_t input_count = cursor.compact_size();
    if (input_count == 0)
        throw std::invalid_argument("IPC block transaction has no inputs");
    for (uint64_t input = 0; input < input_count; ++input) {
        cursor.skip(36); // prevout
        cursor.skip_compact_bytes();
        cursor.skip(sizeof(uint32_t)); // nSequence
    }

    const uint64_t output_count = cursor.compact_size();
    for (uint64_t output = 0; output < output_count; ++output) {
        cursor.skip(sizeof(uint64_t)); // amount
        cursor.skip_compact_bytes();
    }

    if (has_witness) {
        for (uint64_t input = 0; input < input_count; ++input) {
            const uint64_t item_count = cursor.compact_size();
            for (uint64_t item = 0; item < item_count; ++item)
                cursor.skip_compact_bytes();
        }
    }

    cursor.skip(sizeof(uint32_t)); // nLockTime
}

void fill_header_fields(BlockTemplate& block_template, ByteView header) {
    if (header.size() != util::kHeaderSize)
        throw std::invalid_argument("IPC block header must be exactly 80 bytes");
    block_template.version = util::read_le32(header.data() + util::kVersionOffset);
    block_template.curtime = util::read_le32(header.data() + util::kTimeOffset);
    block_template.bits = util::read_le32(header.data() + util::kBitsOffset);
    block_template.bits_hex =
        util::to_hex_reversed(header.subspan(util::kBitsOffset, sizeof(uint32_t)));
    block_template.previousblockhash = util::to_hex_reversed(
        header.subspan(util::kPrevhashOffset, util::kMerkleOffset - util::kPrevhashOffset));
}

} // namespace

CoinbaseOutput parse_coinbase_output(ByteView serialized) {
    Cursor cursor(serialized);
    const uint64_t value = util::read_le64(cursor.take(sizeof(uint64_t)).data());
    if (value > kMaxMoney)
        throw std::invalid_argument("IPC required coinbase output value is out of range");
    const uint64_t script_size = cursor.compact_size();
    if (script_size > cursor.remaining())
        throw std::invalid_argument("IPC required coinbase output script is truncated");
    const ByteView script = cursor.take(static_cast<size_t>(script_size));
    if (cursor.remaining() != 0)
        throw std::invalid_argument("IPC required coinbase output has trailing data");
    return {value, Bytes(script.begin(), script.end())};
}

void fill_block_fields(BlockTemplate& block_template, ByteView block) {
    if (block.size() <= util::kHeaderSize)
        throw std::invalid_argument("IPC block is missing its transaction count");

    fill_header_fields(block_template, block.first(util::kHeaderSize));
    Cursor cursor(block.subspan(util::kHeaderSize));
    const uint64_t total_transactions = cursor.compact_size();
    if (total_transactions == 0)
        throw std::invalid_argument("IPC block contains no coinbase transaction");
    if (total_transactions > std::numeric_limits<uint32_t>::max())
        throw std::invalid_argument("IPC block contains too many transactions");
    skip_transaction(cursor); // Core's dummy coinbase is replaced by the pool's coinbase.
    const size_t transaction_data_offset = util::kHeaderSize + cursor.offset();
    block_template.txn_count = static_cast<uint32_t>(total_transactions - 1);
    const ByteView transaction_data = block.subspan(transaction_data_offset);
    block_template.txn_data.assign(transaction_data.begin(), transaction_data.end());
}

} // namespace erikslund::bitcoin
