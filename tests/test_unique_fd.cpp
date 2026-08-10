#include <doctest/doctest.h>

#include <fcntl.h>
#include <unistd.h>

#include <utility>

#include "util/unique_fd.hpp"

using erikslund::util::UniqueFd;

namespace {
// A fresh real descriptor the test can own; dup of stderr always succeeds.
int fresh_fd() { return ::dup(STDERR_FILENO); }
bool fd_open(int fd) { return ::fcntl(fd, F_GETFD) != -1; }
} // namespace

TEST_CASE("UniqueFd default-constructs empty") {
    UniqueFd fd;
    CHECK_FALSE(static_cast<bool>(fd));
    CHECK(fd.get() == -1);
}

TEST_CASE("UniqueFd adopts a descriptor and closes it on destruction") {
    const int raw = fresh_fd();
    REQUIRE(raw >= 0);
    REQUIRE(fd_open(raw));
    {
        UniqueFd fd(raw);
        CHECK(static_cast<bool>(fd));
        CHECK(fd.get() == raw);
    }
    CHECK_FALSE(fd_open(raw)); // dtor closed it
}

TEST_CASE("UniqueFd move-construction transfers ownership, emptying the source") {
    const int raw = fresh_fd();
    REQUIRE(raw >= 0);
    UniqueFd a(raw);
    UniqueFd b(std::move(a));
    CHECK(b.get() == raw);
    CHECK_FALSE(static_cast<bool>(a)); // moved-from is empty
    CHECK(fd_open(raw));               // still open, now owned by b
}

TEST_CASE("UniqueFd move-assignment closes the displaced descriptor") {
    const int first = fresh_fd();
    const int second = fresh_fd();
    REQUIRE(first >= 0);
    REQUIRE(second >= 0);
    UniqueFd a(first);
    {
        UniqueFd b(second);
        a = std::move(b); // a closes `first`, adopts `second`
    }                     // b destroyed empty -> does not touch `second`
    CHECK_FALSE(fd_open(first)); // displaced -> closed
    CHECK(fd_open(second));      // owned by a -> still open
    CHECK(a.get() == second);
}

TEST_CASE("UniqueFd release relinquishes ownership without closing") {
    const int raw = fresh_fd();
    REQUIRE(raw >= 0);
    {
        UniqueFd fd(raw);
        const int released = fd.release();
        CHECK(released == raw);
        CHECK_FALSE(static_cast<bool>(fd)); // emptied
    }
    CHECK(fd_open(raw)); // dtor did NOT close it
    ::close(raw);        // caller is now responsible
}

TEST_CASE("UniqueFd reset closes the current descriptor") {
    const int raw = fresh_fd();
    REQUIRE(raw >= 0);
    UniqueFd fd(raw);
    fd.reset();
    CHECK_FALSE(static_cast<bool>(fd));
    CHECK_FALSE(fd_open(raw)); // reset closed it
}
