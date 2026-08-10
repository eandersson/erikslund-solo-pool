#include "bitcoin/capnp_mining_client.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <exception>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

#include <capnp/ez-rpc.h>
#include <kj/async.h>
#include <kj/async-io.h>
#include <kj/common.h>
#include <kj/timer.h>

#include "core/errors.hpp"
#include "core/logging.hpp"
#include "init.capnp.h"   // generated: ipc::capnp::messages::Init
#include "mining.capnp.h" // generated: ipc::capnp::messages::Mining, BlockTemplate
#include "mp/proxy.capnp.h" // generated: mp::ThreadMap, Thread

namespace erikslund::bitcoin {

namespace messages = ipc::capnp::messages;

namespace {
constexpr kj::Duration kIpcCallTimeout = 10 * kj::SECONDS;
constexpr kj::Duration kIpcInterruptTimeout = 1 * kj::SECONDS;
constexpr std::chrono::seconds kIpcReconnectDelay{30};

template <typename Func>
auto sync_call(const kj::Executor& executor, Func&& func) {
    try {
        return executor.executeSync(std::forward<Func>(func));
    } catch (const kj::Exception& e) {
        throw RpcConnectionError(std::string("IPC call failed: ") + e.getDescription().cStr());
    }
}

template <typename Response>
auto require_result(Response& response, const char* message) {
    if (!response.hasResult())
        throw RpcConnectionError(message);
    return response.getResult();
}

template <typename Request>
void set_context(Request& request, mp::Thread::Client& server_thread) {
    request.initContext().setThread(server_thread);
}

kj::Timer& require_timer(kj::Timer* timer) {
    if (timer == nullptr)
        throw RpcConnectionError("IPC event-loop timer is not running");
    return *timer;
}

kj::Promise<void> destroy_block_template(messages::BlockTemplate::Client block_template,
                                         mp::Thread::Client& server_thread) {
    auto request = block_template.destroyRequest();
    set_context(request, server_thread);
    return request.send().ignoreResult();
}

bool is_witness_commitment(const CoinbaseOutput& output) {
    constexpr std::array<uint8_t, 6> prefix = {0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed};
    constexpr size_t kCommitmentSize = 38;
    return output.script.size() >= kCommitmentSize &&
           std::equal(prefix.begin(), prefix.end(), output.script.begin());
}

void validate_template(const BlockTemplate& block_template) {
    uint64_t width = static_cast<uint64_t>(block_template.txn_count) + 1;
    size_t expected_depth = 0;
    while (width > 1) {
        width = (width + 1) / 2;
        ++expected_depth;
    }
    if (block_template.merkle_branch_internal.size() != expected_depth)
        throw std::runtime_error("IPC template returned an inconsistent coinbase merkle path");
    const bool has_commitment =
        std::ranges::any_of(block_template.coinbase_required_outputs, is_witness_commitment);
    if (block_template.coinbase_witness.has_value() != has_commitment)
        throw std::runtime_error(
            "IPC template returned inconsistent coinbase witness requirements");
}
} // namespace

// Cap'n Proto objects stay on one event-loop thread. Pool threads marshal calls through a
// reference-counted executor snapshot so reconnect cannot leave a dangling cross-thread pointer.
struct CapnpMiningClient::Impl {
    std::jthread loop_thread;
    std::atomic<bool> connected{false};
    std::atomic<bool> stopping{false};
    std::mutex executor_mutex;
    kj::Own<const kj::Executor> executor;
    kj::Timer* timer = nullptr; // loop-thread-only; owned by EzRpcClient
    kj::Own<kj::PromiseFulfiller<void>> session_done;
    kj::Maybe<messages::Mining::Client> mining;
    mp::Thread::Client server_thread{nullptr};

    std::mutex retry_mutex;
    std::condition_variable retry_cv;

    kj::Own<const kj::Executor> executor_snapshot() {
        const std::scoped_lock lock(executor_mutex);
        if (!executor)
            return {};
        return executor->addRef();
    }

    bool is_current_executor(const kj::Executor& candidate) {
        const std::scoped_lock lock(executor_mutex);
        return executor && executor.get() == &candidate;
    }

    bool publish_executor() {
        const std::scoped_lock lock(executor_mutex);
        if (stopping.load(std::memory_order_acquire))
            return false;
        executor = kj::getCurrentThreadExecutor().addRef();
        connected.store(true, std::memory_order_release);
        return true;
    }

    void clear_session() {
        connected.store(false, std::memory_order_release);
        {
            const std::scoped_lock lock(executor_mutex);
            executor = nullptr;
        }
        session_done = nullptr;
        mining = nullptr;
        server_thread = nullptr;
        timer = nullptr;
    }
};

CapnpMiningClient::CapnpMiningClient(const std::string& socket_path)
    : impl_(std::make_unique<Impl>()) {
    impl_->loop_thread = std::jthread([this, socket_path](const std::stop_token& stop) {
        bool failure_reported = false;
        while (!stop.stop_requested()) {
            std::string failure;
            try {
                capnp::EzRpcClient client("unix:" + socket_path);
                kj::WaitScope& wait_scope = client.getWaitScope();
                kj::Timer& timer = client.getIoProvider().getTimer();
                messages::Init::Client init = client.getMain<messages::Init>();

                // Mining has no callbacks, so only the server half of the bidirectional
                // thread-map handshake is needed.
                auto construct_request = init.constructRequest();
                auto construct_response =
                    timer.timeoutAfter(kIpcCallTimeout, construct_request.send()).wait(wait_scope);
                if (!construct_response.hasThreadMap())
                    throw RpcConnectionError("IPC bootstrap returned no thread map");
                if (stop.stop_requested())
                    return;
                mp::ThreadMap::Client thread_map = construct_response.getThreadMap();

                auto thread_request = thread_map.makeThreadRequest();
                thread_request.setName("erikslund-pool");
                auto thread_response =
                    timer.timeoutAfter(kIpcCallTimeout, thread_request.send()).wait(wait_scope);
                mp::Thread::Client server_thread =
                    require_result(thread_response, "IPC bootstrap returned no server thread");
                if (stop.stop_requested())
                    return;

                auto make_request = init.makeMiningRequest();
                set_context(make_request, server_thread);
                auto mining_response =
                    timer.timeoutAfter(kIpcCallTimeout, make_request.send()).wait(wait_scope);
                messages::Mining::Client mining =
                    require_result(mining_response, "IPC bootstrap returned no Mining capability");
                if (stop.stop_requested())
                    return;

                auto session = kj::newPromiseAndFulfiller<void>();
                impl_->mining = kj::mv(mining);
                impl_->server_thread = kj::mv(server_thread);
                impl_->timer = &timer;
                impl_->session_done = kj::mv(session.fulfiller);
                if (!impl_->publish_executor()) {
                    impl_->clear_session();
                    return;
                }
                failure_reported = false;
                session.promise.wait(wait_scope);
                impl_->clear_session();
            } catch (const kj::Exception& e) {
                failure = e.getDescription().cStr();
            } catch (const std::exception& e) {
                failure = e.what();
            } catch (...) {
                failure = "unknown error";
            }

            impl_->clear_session();
            if (stop.stop_requested())
                break;
            if (!failure.empty()) {
                if (failure_reported)
                    log::debug("IPC reconnect failed: {}", failure);
                else
                    log::warning("IPC unavailable ({}); retrying every {} seconds", failure,
                                 kIpcReconnectDelay.count());
                failure_reported = true;
            }

            std::unique_lock<std::mutex> lock(impl_->retry_mutex);
            impl_->retry_cv.wait_for(lock, kIpcReconnectDelay,
                                     [&stop] { return stop.stop_requested(); });
        }
        impl_->clear_session();
    });
}

CapnpMiningClient::~CapnpMiningClient() {
    interrupt();
    if (impl_->loop_thread.joinable())
        impl_->loop_thread.join();
}

bool CapnpMiningClient::available() const noexcept {
    return impl_->connected.load(std::memory_order_acquire) &&
           !impl_->stopping.load(std::memory_order_acquire);
}

BlockTemplate CapnpMiningClient::create_block() {
    kj::Own<const kj::Executor> executor = impl_->executor_snapshot();
    if (!executor)
        throw RpcConnectionError("IPC is reconnecting");
    const auto request_block = [this]() -> kj::Promise<BlockTemplate> {
        kj::Timer& timer = require_timer(impl_->timer);
        auto request = KJ_ASSERT_NONNULL(impl_->mining).createNewBlockRequest();
        set_context(request, impl_->server_thread);
        request.initOptions().setUseMempool(true);
        request.setCooldown(false);
        auto response_promise =
            request.send().then([this](auto&& create_response) -> kj::Promise<BlockTemplate> {
                messages::BlockTemplate::Client block_template =
                    require_result(create_response, "IPC createNewBlock returned no template");
                messages::BlockTemplate::Client cleanup_template = block_template;
                auto output = kj::heap<BlockTemplate>();
                BlockTemplate& fields = *output;
                auto requests = kj::heapArrayBuilder<kj::Promise<void>>(3);
                auto block_request = block_template.getBlockRequest();
                set_context(block_request, impl_->server_thread);
                requests.add(block_request.send().then([&fields](auto&& response) {
                    const auto block =
                        require_result(response, "IPC template returned no block");
                    fill_block_fields(fields, ByteView(block.begin(), block.size()));
                }));
                auto coinbase_request = block_template.getCoinbaseTxRequest();
                set_context(coinbase_request, impl_->server_thread);
                requests.add(coinbase_request.send().then([&fields](auto&& response) {
                    const auto coinbase =
                        require_result(response, "IPC template returned no coinbase data");
                    const int64_t reward = coinbase.getBlockRewardRemaining();
                    if (reward < 0)
                        throw std::runtime_error(
                            "IPC template returned a negative coinbase reward");
                    fields.coinbase_version = coinbase.getVersion();
                    fields.coinbase_sequence = coinbase.getSequence();
                    const auto prefix = coinbase.getScriptSigPrefix();
                    fields.coinbase_script_sig_prefix.assign(prefix.begin(), prefix.end());
                    if (fields.coinbase_script_sig_prefix.empty())
                        throw std::runtime_error(
                            "IPC template returned an empty coinbase scriptSig prefix");
                    const auto witness = coinbase.getWitness();
                    if (witness.size() != 0) {
                        if (witness.size() != 32)
                            throw std::runtime_error(
                                "IPC template coinbase witness is not 32 bytes");
                        fields.coinbase_witness = Bytes(witness.begin(), witness.end());
                    }
                    const auto required_outputs = coinbase.getRequiredOutputs();
                    fields.coinbase_required_outputs.reserve(required_outputs.size());
                    for (const auto required_output : required_outputs)
                        fields.coinbase_required_outputs.push_back(parse_coinbase_output(
                            ByteView(required_output.begin(), required_output.size())));
                    fields.coinbase_value = static_cast<uint64_t>(reward);
                    fields.coinbase_lock_time = coinbase.getLockTime();
                    // Mining IPC does not expose height. Core currently encodes height - 1 here;
                    // IpcWorkSource verifies the inferred height against the authoritative RPC tip.
                    fields.height = static_cast<int64_t>(fields.coinbase_lock_time) + 1;
                }));
                auto merkle_request = block_template.getCoinbaseMerklePathRequest();
                set_context(merkle_request, impl_->server_thread);
                requests.add(merkle_request.send().then([&fields](auto&& response) {
                    const auto path =
                        require_result(response, "IPC template returned no coinbase merkle path");
                    fields.merkle_branch_internal.reserve(path.size());
                    for (const auto node : path) {
                        if (node.size() != 32)
                            throw std::runtime_error(
                                "IPC template merkle path node is not 32 bytes");
                        util::Hash256 hash{};
                        std::copy(node.begin(), node.end(), hash.begin());
                        fields.merkle_branch_internal.push_back(hash);
                    }
                }));
                auto inspection_promise = kj::joinPromises(requests.finish());
                auto validated_promise = inspection_promise.then([&fields] {
                    validate_template(fields);
                });
                return validated_promise.then(
                    [this, block_template = kj::mv(block_template),
                        output = kj::mv(output)]() mutable -> kj::Promise<BlockTemplate> {
                        return destroy_block_template(
                                   kj::mv(block_template), impl_->server_thread)
                            .then([output = kj::mv(output)]() mutable {
                                return kj::mv(*output);
                            });
                    },
                    [this, block_template = kj::mv(cleanup_template)](
                        kj::Exception&& failure) mutable -> kj::Promise<BlockTemplate> {
                        return destroy_block_template(
                                   kj::mv(block_template), impl_->server_thread)
                            .then([failure = kj::mv(failure)]() mutable
                                  -> kj::Promise<BlockTemplate> {
                                return kj::Promise<BlockTemplate>(kj::mv(failure));
                            });
                    });
            });
        return timer.timeoutAfter(kIpcCallTimeout, kj::mv(response_promise));
    };
    try {
        return sync_call(*executor, request_block);
    } catch (...) {
        cancel_active_call(*executor);
        retire_session(*executor);
        throw;
    }
}

void CapnpMiningClient::cancel_active_call(const kj::Executor& executor) noexcept {
    try {
        executor.executeSync([this]() -> kj::Promise<void> {
            kj::Timer& timer = require_timer(impl_->timer);
            auto response_promise =
                KJ_ASSERT_NONNULL(impl_->mining).interruptRequest().send().ignoreResult();
            return timer.timeoutAfter(kIpcInterruptTimeout, kj::mv(response_promise));
        });
    } catch (const std::exception& e) {
        log::debug("IPC interrupt failed: {}", e.what());
    } catch (...) {
        log::debug("IPC interrupt failed");
    }
}

void CapnpMiningClient::retire_session(const kj::Executor& executor) noexcept {
    if (!impl_->is_current_executor(executor))
        return;
    impl_->connected.store(false, std::memory_order_release);
    try {
        executor.executeSync([this] {
            impl_->mining = nullptr;
            impl_->server_thread = nullptr;
            if (impl_->session_done) {
                auto done = kj::mv(impl_->session_done);
                done->fulfill();
            }
        });
    } catch (const std::exception& e) {
        log::debug("IPC session was already stopped: {}", e.what());
    } catch (...) {
        log::debug("IPC session was already stopped");
    }
}

void CapnpMiningClient::interrupt() noexcept {
    if (impl_->stopping.exchange(true, std::memory_order_acq_rel))
        return;
    impl_->loop_thread.request_stop();
    try {
        kj::Own<const kj::Executor> executor = impl_->executor_snapshot();
        if (executor) {
            cancel_active_call(*executor);
            retire_session(*executor);
        }
    } catch (const std::exception& e) {
        log::debug("IPC shutdown raced with session teardown: {}", e.what());
    } catch (...) {
        log::debug("IPC shutdown raced with session teardown");
    }
    impl_->retry_cv.notify_all();
}

} // namespace erikslund::bitcoin
