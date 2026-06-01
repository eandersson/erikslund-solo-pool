#include "core/logging.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <mutex>
#include <string>
#include <string_view>
#include <system_error>

namespace erikslund::log {

namespace {

std::atomic<Level> g_level{Level::Info};
std::mutex g_write_mutex;
std::FILE* g_log_file = nullptr;

const char* level_name(Level level) {
    switch (level) {
    case Level::Debug:
        return "DEBUG";
    case Level::Info:
        return "INFO";
    case Level::Notice:
        return "NOTICE";
    case Level::Warning:
        return "WARNING";
    case Level::Error:
        return "ERROR";
    }
    return "?";
}

} // namespace

void set_level(Level level) {
    g_level.store(level, std::memory_order_relaxed);
}

Level level() {
    return g_level.load(std::memory_order_relaxed);
}

bool set_log_file(std::string_view path) {
    const std::lock_guard<std::mutex> lock(g_write_mutex);
    if (g_log_file) {
        std::fclose(g_log_file);
        g_log_file = nullptr;
    }
    if (path.empty())
        return true;
    const std::filesystem::path file_path(path);
    if (file_path.has_parent_path()) {
        std::error_code ec;
        std::filesystem::create_directories(file_path.parent_path(), ec);
    }
    g_log_file = std::fopen(std::string(path).c_str(), "a");
    return g_log_file != nullptr;
}

void write(Level level, std::string_view message) {
    const auto now = std::chrono::system_clock::now();
    const std::time_t seconds = std::chrono::system_clock::to_time_t(now);
    std::tm local_time{};
#if defined(_WIN32)
    localtime_s(&local_time, &seconds);
#else
    localtime_r(&seconds, &local_time);
#endif
    char timestamp[32];
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &local_time);
    const auto milliseconds =
        std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    const long long ms = static_cast<long long>(milliseconds.count());

    // Line shape "[time.ms] LEVEL message". %.*s prints the string_view directly, no NUL-copy.
    const auto emit = [&](std::FILE* stream) {
        std::fprintf(stream, "[%s.%03lld] %-7s %.*s\n", timestamp, ms, level_name(level),
                     static_cast<int>(message.size()), message.data());
        std::fflush(stream);
    };

    const std::lock_guard<std::mutex> lock(g_write_mutex);
    emit(stderr);
    if (g_log_file)
        emit(g_log_file);
}

std::string sanitize(std::string_view value, size_t limit) {
    if (value.empty())
        return "?";
    std::string out;
    for (const char c : value) {
        if (out.size() >= limit)
            break;
        const auto byte = static_cast<unsigned char>(c);
        out += (byte >= 0x20 && byte != 0x7f) ? c : '?';
    }
    return out;
}

std::string ascii_only(std::string_view value, size_t limit) {
    std::string out;
    for (const char c : value) {
        if (out.size() >= limit) // cap AFTER dropping (result is ASCII: byte-count == char-count)
            break;
        const auto byte = static_cast<unsigned char>(c);
        if (byte >= 0x20 && byte <= 0x7e) // drop control, DEL, and every non-ASCII byte
            out += c;
    }
    return out;
}

} // namespace erikslund::log
