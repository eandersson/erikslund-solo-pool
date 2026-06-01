#pragma once

namespace erikslund::core {

// Handle fatal signals (SIGSEGV/SIGABRT/SIGBUS/SIGFPE/SIGILL) and uncaught exceptions: log a
// backtrace to stderr, then re-raise for the default action (preserving exit code / core dump).
// SIGKILL can't be caught, so an OOM-kill leaves no backtrace -- watch RSS and the oom-killer log.
void install_crash_handlers();

} // namespace erikslund::core
