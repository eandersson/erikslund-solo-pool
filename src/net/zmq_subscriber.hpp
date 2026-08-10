#pragma once
// Subscribes to bitcoind ZMQ hashblock and wakes the work loop on each new block.
#include <stop_token>
#include <string>

#include "pool/pool.hpp"

namespace erikslund::net {

class ZmqSubscriber {
public:
    ZmqSubscriber(Pool& pool, std::string endpoint);

    // Connect + receive until `stop`. Failures are logged and retried; never throws.
    void run(const std::stop_token& stop);

private:
    Pool& pool_;
    std::string endpoint_;
};

} // namespace erikslund::net
