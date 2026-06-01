// Entry point: load config, connect to bitcoind, start the server, run until signal.
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <exception>
#include <optional>
#include <stop_token>
#include <string>
#include <thread>

#include <sys/resource.h>

#include "api/http_server.hpp"
#include "bitcoin/rpc_client.hpp"
#include "core/config.hpp"
#include "core/crash.hpp"
#include "core/logging.hpp"
#include "core/version.hpp"
#include "net/server.hpp"
#include "net/zmq_subscriber.hpp"
#include "pool/pool.hpp"
#include "util/sha256.hpp"
#include "util/url.hpp"

#ifdef HAVE_MIMALLOC
#include <mimalloc.h>
#endif

namespace {
std::atomic<bool> g_shutdown{false};
extern "C" void handle_signal(int /*signum*/) {
    g_shutdown.store(true);
}
} // namespace

int main(int argc, char** argv) {
    using namespace erikslund;

    core::install_crash_handlers(); // log a backtrace on SIGSEGV/abort/uncaught exception

    std::string config_path;
    std::string log_file;
    std::optional<std::string> api_host_override;
    std::optional<uint16_t> api_port_override;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--config" && i + 1 < argc)
            config_path = argv[++i];
        else if (arg == "--api-host" && i + 1 < argc)
            api_host_override = argv[++i];
        else if (arg == "--api-port" && i + 1 < argc)
            api_port_override = static_cast<uint16_t>(std::stoul(argv[++i]));
        else if (arg == "--log-file" && i + 1 < argc)
            log_file = argv[++i];
        else if (arg == "--debug")
            log::set_level(log::Level::Debug);
        else if (arg == "--quiet")
            log::set_level(log::Level::Warning);
    }

    if (!log_file.empty() && !log::set_log_file(log_file))
        log::warning("Cannot open log file '{}'; logging to stderr only", log_file);

    Config config;
    try {
        if (!config_path.empty())
            config = Config::from_file(config_path);
    } catch (const std::exception& e) {
        log::error("Config error: {}", e.what());
        return 1;
    }
    // CLI overrides win over the file.
    if (api_host_override)
        config.api_host = *api_host_override;
    if (api_port_override)
        config.api_port = *api_port_override;

    log::info("erikslund-solo-pool v{} starting -- stratum {}:{}, bitcoind {}", kVersion,
                config.bind_host, config.bind_port, util::redact_url(config.rpc_url));
    long open_file_limit = -1; // -1 means unlimited / unavailable
    if (rlimit nofile{}; ::getrlimit(RLIMIT_NOFILE, &nofile) == 0 && nofile.rlim_cur != RLIM_INFINITY)
        open_file_limit = static_cast<long>(nofile.rlim_cur);
    if (open_file_limit >= 0 && config.max_clients > open_file_limit) {
        log::warning("max_clients ({}) exceeds the open file limit ({}); lowering to {} "
                     "-- raise it (ulimit -n / LimitNOFILE) to allow more",
                     config.max_clients, open_file_limit, open_file_limit);
        config.max_clients = static_cast<int>(open_file_limit);
    }
    const std::string open_file_limit_text =
        open_file_limit < 0 ? std::string("unlimited") : std::to_string(open_file_limit);
    log::info("Max clients: {} (open file limit of {})", config.max_clients, open_file_limit_text);
#ifdef HAVE_MIMALLOC
    const int mimalloc_version = mi_version();
    log::info("allocator: mimalloc {}.{}.{}", mimalloc_version / 100, (mimalloc_version / 10) % 10,
                mimalloc_version % 10);
    // Return freed pages to the OS promptly; lower RSS beats page reuse here.
    mi_option_set(mi_option_purge_delay, 0);
#endif
    log::info("sha256 backend: {}", util::sha256_init());

    bitcoin::RpcClient rpc(config.rpc_endpoints());
    if (!config.rpc_failover.empty())
        log::info("Bitcoind failover: {} endpoint(s) configured", config.rpc_endpoints().size());
    Pool pool(config, rpc);

    // Install handlers before waiting on bitcoind so Ctrl-C / SIGTERM can interrupt the wait.
    // SIGPIPE ignored so a broken socket write never kills the process.
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);
    std::signal(SIGPIPE, SIG_IGN);

    // Retry rather than exit on first failure: bitcoind may still be warming up or its socket not
    // yet open. detect_network sets the network used for local address validation, so we can't
    // serve until it succeeds -- but we stay up and keep probing.
    bool network_detected = false;
    for (int attempt = 0; !network_detected && !g_shutdown.load(); ++attempt) {
        try {
            pool.detect_network();
            network_detected = true;
        } catch (const std::exception& e) {
            if (attempt == 0)
                log::warning("Waiting for bitcoind at {}: {} (will keep retrying)",
                             util::redact_url(config.rpc_url), e.what());
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    }
    if (!network_detected)
        return 0; // shutdown requested while waiting for bitcoind

    pool.recover_stats();           // resume cumulative stats from a prior pool.status
    pool.recover_user_stats();      // resume per-worker stats (hashrates decayed by file age)
    pool.resubmit_spooled_blocks(); // re-submit any block a previous run couldn't confirm

    net::Server server(pool, config);
    try {
        server.start();
    } catch (const std::exception& e) {
        log::error("Cannot start stratum server: {}", e.what());
        return 1;
    }
    pool.set_connector_ready(true);

    // HTTP status / metrics API -- non-fatal if its port is unavailable.
    api::HttpServer api_server(pool, config.api_host, config.api_port);
    bool api_up = false;
    try {
        api_server.start();
        api_up = true;
    } catch (const std::exception& e) {
        log::warning("HTTP API disabled: {}", e.what());
    }

    std::stop_source stop;
    // request_stop isn't async-signal-safe, so a watcher polls the signal flag.
    std::jthread watcher([&stop] {
        while (!g_shutdown.load() && !stop.stop_requested())
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        stop.request_stop();
    });
    // Each thread guards its body: a throw escaping a jthread calls std::terminate().
    std::jthread worker([&pool, &stop] {
        try {
            pool.refresh_work(stop.get_token());
        } catch (const std::exception& e) {
            log::error("work thread crashed: {}", e.what());
        }
    });
    std::jthread vardiff_thread([&pool, &stop] {
        try {
            pool.vardiff_loop(stop.get_token());
        } catch (const std::exception& e) {
            log::error("vardiff thread crashed: {}", e.what());
        }
    });
    std::jthread status_thread([&pool, &stop] {
        try {
            pool.status_loop(stop.get_token());
        } catch (const std::exception& e) {
            log::error("status thread crashed: {}", e.what());
        }
    });
    std::jthread api_thread;
    if (api_up)
        api_thread = std::jthread([&api_server, &stop] {
            try {
                api_server.run(stop.get_token());
            } catch (const std::exception& e) {
                log::error("api thread crashed: {}", e.what());
            }
        });
    std::jthread zmq_thread;
    if (!config.zmq_block_endpoint.empty())
        zmq_thread = std::jthread([&pool, &config, &stop] {
            try {
                net::ZmqSubscriber subscriber(pool, config.zmq_block_endpoint);
                subscriber.run(stop.get_token());
            } catch (const std::exception& e) {
                log::error("zmq thread crashed: {}", e.what());
            }
        });

    server.run(stop.get_token());
    stop.request_stop();

    log::info("Shutdown complete -- {} shares accepted, {} blocks found", pool.accepted_shares(),
                pool.blocks_found());
    return 0;
}
