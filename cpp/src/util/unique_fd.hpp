#pragma once
// Move-only owning wrapper around a file descriptor: closes on scope exit so no
// early return or exception can leak it. Mirrors SocketConnection's closing dtor.
#include <unistd.h>

#include <utility>

namespace erikslund::util {

class UniqueFd {
public:
    UniqueFd() = default;
    explicit UniqueFd(int fd) noexcept : fd_(fd) {}

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    UniqueFd(UniqueFd&& other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
    UniqueFd& operator=(UniqueFd&& other) noexcept {
        if (this != &other)
            reset(other.release());
        return *this;
    }

    ~UniqueFd() { reset(); }

    [[nodiscard]] int get() const noexcept { return fd_; }
    explicit operator bool() const noexcept { return fd_ >= 0; }

    // Relinquish ownership without closing; the caller becomes responsible.
    [[nodiscard]] int release() noexcept { return std::exchange(fd_, -1); }

    // Close the held descriptor (if any) and adopt another.
    void reset(int fd = -1) noexcept {
        if (fd_ >= 0)
            ::close(fd_);
        fd_ = fd;
    }

private:
    int fd_ = -1;
};

} // namespace erikslund::util
