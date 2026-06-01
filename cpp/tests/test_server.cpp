#include <doctest/doctest.h>

#include "net/server.hpp"

using namespace erikslund::net;

TEST_CASE("resolve_worker_count honors an explicit count and clamps auto") {
    CHECK(resolve_worker_count(4) == 4u);
    CHECK(resolve_worker_count(100) == 100u); // explicit is unclamped

    // 0 = auto: clamped so a cgroup CPU quota can't over-thread.
    const unsigned auto_count = resolve_worker_count(0);
    CHECK(auto_count >= 1u);
    CHECK(auto_count <= 16u);
}

TEST_CASE("an explicit single worker is honored") {
    CHECK(resolve_worker_count(1) == 1u);
}

TEST_CASE("a negative configured count is treated as auto") {
    // configured <= 0 falls into the auto branch (clamped 1..16).
    const unsigned auto_count = resolve_worker_count(-1);
    CHECK(auto_count >= 1u);
    CHECK(auto_count <= 16u);
    // Auto is deterministic on a given host: two calls agree.
    CHECK(resolve_worker_count(-1) == resolve_worker_count(0));
}
