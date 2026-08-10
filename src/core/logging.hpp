#pragma once
// Thread-safe, level-gated logger: timestamped std::format lines to stderr (and optionally a file).
#include <cstddef>
#include <format>
#include <string>
#include <string_view>
#include <utility>

namespace erikslund::log {

enum class Level { Debug = 0, Info, Notice, Warning, Error };

void set_level(Level level);
Level level();

// Write one already-formatted line. Prefer the typed helpers below.
void write(Level level, std::string_view message);

// Sanitize an untrusted miner-controlled string (worker name, user-agent) before storing or
// logging: replace control chars (anti log-injection) and hard-cap length. "?" for empty input.
std::string sanitize(std::string_view value, size_t limit = 128);

// Keep only printable-ASCII bytes (0x20-0x7e), dropping anything else, then cap to `limit` bytes.
// The worker name goes into the ASCII-only users/<address> stats file, where a non-ASCII byte
// corrupts the file. Dropping (not replacing) and capping after keep the result ASCII so byte-count
// == char-count. Cosmetic; apply to the RAW (un-sanitized) suffix.
std::string ascii_only(std::string_view value, size_t limit = 128);

// Also append every log line to `path` (parent dirs created); empty path disables file logging.
// Returns false if the file can't be opened. Rotation is the OS's job. Set once at startup.
bool set_log_file(std::string_view path);

template <class... Args>
void message(Level level, std::format_string<Args...> fmt, Args&&... args) {
    if (level >= log::level())
        write(level, std::format(fmt, std::forward<Args>(args)...));
}

template <class... Args>
void debug(std::format_string<Args...> fmt, Args&&... args) {
    message(Level::Debug, fmt, std::forward<Args>(args)...);
}
template <class... Args>
void info(std::format_string<Args...> fmt, Args&&... args) {
    message(Level::Info, fmt, std::forward<Args>(args)...);
}
template <class... Args>
void notice(std::format_string<Args...> fmt, Args&&... args) {
    message(Level::Notice, fmt, std::forward<Args>(args)...);
}
template <class... Args>
void warning(std::format_string<Args...> fmt, Args&&... args) {
    message(Level::Warning, fmt, std::forward<Args>(args)...);
}
template <class... Args>
void error(std::format_string<Args...> fmt, Args&&... args) {
    message(Level::Error, fmt, std::forward<Args>(args)...);
}

} // namespace erikslund::log
