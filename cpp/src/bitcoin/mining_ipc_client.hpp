#pragma once
// Cap'n Proto-free seam around the Mining IPC calls used by IpcWorkSource.
#include "bitcoin/block_template.hpp"

namespace erikslund::bitcoin {

void fill_block_fields(BlockTemplate& block_template, ByteView block);
CoinbaseOutput parse_coinbase_output(ByteView serialized);

class MiningIpcClient {
public:
    virtual ~MiningIpcClient() = default;

    // True only while a fully bootstrapped IPC session can accept calls.
    virtual bool available() const noexcept = 0;

    // Requests a complete transaction-bearing template. RPC submits the solved block.
    virtual BlockTemplate create_block() = 0;

    // Stops reconnection and cancels an in-flight create_block during shutdown.
    virtual void interrupt() noexcept = 0;
};

} // namespace erikslund::bitcoin
