#include <doctest/doctest.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

#include "core/logging.hpp"

using namespace erikslund;

TEST_CASE("set_log_file tees log lines to an append-only file and disables cleanly") {
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / "erikslund-log-test";
    fs::remove_all(dir);
    const fs::path path = dir / "nested" / "pool.log"; // parent dirs auto-created

    log::set_level(log::Level::Info);
    REQUIRE(log::set_log_file(path.string()));
    log::info("file-sink-{}", 42);
    REQUIRE(log::set_log_file("")); // disable + close so we can read it (and stop teeing)

    std::ifstream in(path);
    REQUIRE(in.good());
    std::stringstream buffer;
    buffer << in.rdbuf();
    const std::string contents = buffer.str();
    CHECK(contents.find("file-sink-42") != std::string::npos);
    CHECK(contents.find("INFO") != std::string::npos);

    fs::remove_all(dir);
}

TEST_CASE("log::sanitize cleans untrusted strings before storing/logging them") {
    CHECK(log::sanitize("bcrt1qexample.rig1") == "bcrt1qexample.rig1");
    CHECK(log::sanitize("cgminer/4.10") == "cgminer/4.10");
    CHECK(log::sanitize("") == "?");
    CHECK(log::sanitize("a\nb") == "a?b");
    CHECK(log::sanitize(std::string("addr\nINFO BLOCK ACCEPTED")).find('\n') == std::string::npos);
    CHECK(log::sanitize("a\r\tb") == "a??b");
    CHECK(log::sanitize("x\x7f""y") == "x?y"); // DEL is stripped too
    const std::string capped = log::sanitize(std::string(200, 'x'), 64);
    CHECK(capped.size() == 64);
    CHECK(capped == std::string(64, 'x'));
}

TEST_CASE("log::ascii_only drops non-ASCII so a worker name stays ASCII for the stats file") {
    CHECK(log::ascii_only("rig1") == "rig1");
    CHECK(log::ascii_only("rig.worker_2") == "rig.worker_2");
    // "rigé" (é = UTF-8 0xC3 0xA9): both high bytes are dropped, leaving the ASCII skeleton.
    CHECK(log::ascii_only(std::string("rig\xC3\xA9")) == "rig");
    CHECK(log::ascii_only(std::string("\xE4\xB8\xAD\xE6\x96\x87")) == ""); // all-CJK -> empty
    CHECK(log::ascii_only(std::string("a\xC3\xA9""b")) == "ab");           // interleaved
    CHECK(log::ascii_only("x\x7f""y") == "xy");                            // DEL dropped
    CHECK(log::ascii_only(std::string("c\x01""d")) == "cd");               // control dropped
    CHECK(log::ascii_only("") == "");
    // Unicode-printable-but-not-ASCII (NBSP c2 a0, ZWSP e2 80 8b) dropped.
    CHECK(log::ascii_only(std::string("rig\xC2\xA0""a")) == "riga");
    CHECK(log::ascii_only(std::string("rig\xC2\xA0\xE2\x80\x8b""farm")) == "rigfarm");
    // Cap is applied AFTER dropping non-ASCII bytes.
    CHECK(log::ascii_only(std::string(200, 'a')).size() == 128);
    CHECK(log::ascii_only(std::string(200, 'a'), 10) == std::string(10, 'a'));
}

TEST_CASE("set_log_file returns false when the path cannot be opened") {
    namespace fs = std::filesystem;
    const fs::path not_a_dir = fs::temp_directory_path() / "erikslund-log-not-a-dir";
    { std::ofstream(not_a_dir) << "x"; } // a regular file
    // A path *under a regular file* can't be created/opened.
    CHECK_FALSE(log::set_log_file((not_a_dir / "sub" / "pool.log").string()));
    log::set_log_file(""); // ensure file logging is off for later tests
    fs::remove(not_a_dir);
}
