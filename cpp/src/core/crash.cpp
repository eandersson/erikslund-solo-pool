#include "core/crash.hpp"

#include <csignal>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <initializer_list>

#include <execinfo.h>
#include <unistd.h>

namespace erikslund::core {
namespace {

constexpr int kMaxFrames = 64;

// Async-signal-safe: writes a NUL-terminated string straight to stderr.
void write_stderr(const char* text) {
    const size_t len = std::strlen(text);
    ssize_t written = 0;
    while (written < static_cast<ssize_t>(len)) {
        const ssize_t n = ::write(STDERR_FILENO, text + written, len - static_cast<size_t>(written));
        if (n <= 0)
            break;
        written += n;
    }
}

void write_backtrace() {
    void* frames[kMaxFrames];
    const int n = ::backtrace(frames, kMaxFrames);
    ::backtrace_symbols_fd(frames, n, STDERR_FILENO); // _fd variant mallocs nothing
    write_stderr("*** end backtrace ***\n");
}

const char* signal_name(int signum) {
    switch (signum) {
    case SIGSEGV:
        return "SIGSEGV (segmentation fault)";
    case SIGABRT:
        return "SIGABRT (abort)";
    case SIGBUS:
        return "SIGBUS (bus error)";
    case SIGFPE:
        return "SIGFPE (floating-point exception)";
    case SIGILL:
        return "SIGILL (illegal instruction)";
    default:
        return "fatal signal";
    }
}

extern "C" void handle_fatal_signal(int signum) {
    write_stderr("\n*** ");
    write_stderr(signal_name(signum));
    write_stderr(" -- backtrace (most recent call last) ***\n");
    write_backtrace();
    // Restore the default disposition and re-raise: preserves the exit code / core dump.
    std::signal(signum, SIG_DFL);
    ::raise(signum);
}

[[noreturn]] void handle_terminate() {
    write_stderr("\n*** std::terminate -- uncaught exception ***\n");
    if (const std::exception_ptr eptr = std::current_exception()) {
        try {
            std::rethrow_exception(eptr);
        } catch (const std::exception& e) {
            write_stderr("  what(): ");
            write_stderr(e.what());
            write_stderr("\n");
        } catch (...) {
            write_stderr("  (exception not derived from std::exception)\n");
        }
    }
    write_backtrace();
    std::abort();
}

} // namespace

void install_crash_handlers() {
    // Warm up the unwinder now so the handler never triggers a lazy dlopen mid-crash.
    void* warmup[1];
    (void)::backtrace(warmup, 1);

    for (const int sig : {SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL})
        std::signal(sig, handle_fatal_signal);
    std::set_terminate(handle_terminate);
}

} // namespace erikslund::core
