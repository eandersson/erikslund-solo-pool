#pragma once
// Ordered-byte transport for an SV2 session.
#include "mining/client.hpp"
#include "util/bytes.hpp"

namespace erikslund::sv2 {

class Connection : public virtual mining::Connection {
public:
    ~Connection() override = default;
    virtual void send_bytes(ByteView bytes) = 0;
};

} // namespace erikslund::sv2
