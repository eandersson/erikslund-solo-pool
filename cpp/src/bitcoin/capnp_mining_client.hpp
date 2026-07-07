#pragma once
// Raw Cap'n Proto Mining client for Bitcoin Core's IPC socket.

#include <memory>
#include <string>

#include "bitcoin/mining_ipc_client.hpp"

namespace kj {
class Executor;
}

namespace erikslund::bitcoin {

class CapnpMiningClient final : public MiningIpcClient {
public:
    // Starts a background connection loop. A failed session is replaced after a fixed backoff.
    explicit CapnpMiningClient(const std::string& socket_path);
    ~CapnpMiningClient() override;

    bool available() const noexcept override;

    // Includes Core's selected mempool transactions and their fees.
    BlockTemplate create_block() override;

    void interrupt() noexcept override;

private:
    void cancel_active_call(const kj::Executor& executor) noexcept;
    void retire_session(const kj::Executor& executor) noexcept;

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace erikslund::bitcoin
