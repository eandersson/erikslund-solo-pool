#include "bitcoin/work_source_ipc.hpp"

#include <cstdint>
#include <exception>

#include "core/errors.hpp"
#include "core/logging.hpp"

namespace erikslund::bitcoin {

BlockTemplate IpcWorkSource::fetch_template() {
    if (stopping_.load(std::memory_order_acquire))
        throw RpcConnectionError("IPC work source is stopping");
    if (!client_.available()) {
        ipc_active_.store(false, std::memory_order_relaxed);
        return rpc_.fetch_template();
    }
    BlockTemplate block_template;
    try {
        block_template = client_.create_block();
    } catch (const std::exception& e) {
        ipc_active_.store(false, std::memory_order_relaxed);
        if (stopping_.load(std::memory_order_acquire))
            throw;
        log::warning("IPC fetch_template failed ({}); using RPC for work", e.what());
        return rpc_.fetch_template();
    }
    const std::string expected_tip = rpc_.get_tip();
    if (block_template.previousblockhash != expected_tip) {
        log::debug("IPC template parent {} is not the RPC tip {}; using RPC for this cycle",
                   block_template.previousblockhash, expected_tip);
        return rpc_.fetch_template();
    }

    const HeaderFacts tip = rpc_.fetch_header(expected_tip);
    if (tip.confirmations != 1) {
        log::debug("RPC tip {} changed during IPC template validation; using RPC for this cycle",
                   expected_tip);
        return rpc_.fetch_template();
    }
    if (block_template.height <= 0 || block_template.height - 1 != tip.height) {
        ipc_active_.store(false, std::memory_order_relaxed);
        log::warning("IPC template height {} does not follow RPC tip height {}; using RPC for work",
                     block_template.height, tip.height);
        return rpc_.fetch_template();
    }

    if (!ipc_active_.exchange(true, std::memory_order_relaxed))
        log::info("IPC work source active");
    return block_template;
}

std::vector<std::string> IpcWorkSource::endpoint_urls() const {
    std::vector<std::string> endpoints{endpoint_label_};
    std::vector<std::string> rpc_endpoints = rpc_.endpoint_urls();
    endpoints.insert(endpoints.end(), rpc_endpoints.begin(), rpc_endpoints.end());
    return endpoints;
}

std::size_t IpcWorkSource::active_index() const {
    return ipc_active_.load(std::memory_order_relaxed) && client_.available()
               ? 0
               : rpc_.active_index() + 1;
}

} // namespace erikslund::bitcoin
