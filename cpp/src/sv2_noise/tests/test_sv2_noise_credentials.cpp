#include "credentials.h"
#include "sv2_noise.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

constexpr std::uint32_t kValidFrom = 1'000;
constexpr std::uint32_t kNotValidAfter = 2'000;
constexpr std::uint32_t kValidNow = 1'500;
constexpr mode_t kPermissionMask = S_IRWXU | S_IRWXG | S_IRWXO;
constexpr mode_t kSecretPermissions = S_IRUSR | S_IWUSR;
constexpr std::string_view kAuthorityKeyText =
    "9bXiEd8boQVhq7WddEcERUL5tyyJVFYdU8th3HfbNXK3Yw6GRXh";

void require(bool condition, std::string_view message) {
    if (!condition)
        throw std::runtime_error(std::string(message));
}

void require_status(
    sv2_credentials_status actual,
    sv2_credentials_status expected,
    std::string_view operation) {
    if (actual == expected)
        return;
    throw std::runtime_error(
        std::string(operation) + ": expected " +
        sv2_credentials_status_string(expected) + ", got " +
        sv2_credentials_status_string(actual));
}

class TemporaryDirectory {
public:
    TemporaryDirectory() {
        constexpr std::string_view prefix = "/tmp/sv2-noise-credentials-XXXXXX";
        std::array<char, prefix.size() + 1> pattern{};

        std::ranges::copy(prefix, pattern.begin());
        const auto directory = mkdtemp(pattern.data());
        if (directory == nullptr)
            throw std::system_error(errno, std::generic_category(), "mkdtemp");
        path_ = directory;
    }

    ~TemporaryDirectory() {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    TemporaryDirectory(const TemporaryDirectory&) = delete;
    TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;

    [[nodiscard]] std::filesystem::path file(std::string_view name) const {
        return path_ / name;
    }

    [[nodiscard]] const std::filesystem::path& path() const {
        return path_;
    }

private:
    std::filesystem::path path_;
};

void write_file(
    const std::filesystem::path& path,
    const std::vector<std::uint8_t>& data,
    mode_t mode) {
    const int descriptor = open(
        path.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
        mode);
    if (descriptor < 0)
        throw std::system_error(errno, std::generic_category(), "open");

    std::size_t offset = 0;
    while (offset < data.size()) {
        const auto written = write(
            descriptor,
            data.data() + offset,
            data.size() - offset);
        if (written < 0) {
            const auto saved_errno = errno;
            close(descriptor);
            throw std::system_error(saved_errno, std::generic_category(), "write");
        }
        require(written != 0, "write made no progress");
        offset += static_cast<std::size_t>(written);
    }
    if (close(descriptor) != 0)
        throw std::system_error(errno, std::generic_category(), "close");
    if (chmod(path.c_str(), mode) != 0)
        throw std::system_error(errno, std::generic_category(), "chmod");
}

std::vector<std::uint8_t> read_file(const std::filesystem::path& path) {
    const auto size = std::filesystem::file_size(path);
    std::vector<std::uint8_t> data(size);
    const int descriptor = open(path.c_str(), O_RDONLY | O_CLOEXEC);

    if (descriptor < 0)
        throw std::system_error(errno, std::generic_category(), "open");
    std::size_t offset = 0;
    while (offset < data.size()) {
        const auto bytes_read = read(
            descriptor,
            data.data() + offset,
            data.size() - offset);
        if (bytes_read < 0) {
            const auto saved_errno = errno;
            close(descriptor);
            throw std::system_error(saved_errno, std::generic_category(), "read");
        }
        require(bytes_read != 0, "unexpected end of file");
        offset += static_cast<std::size_t>(bytes_read);
    }
    if (close(descriptor) != 0)
        throw std::system_error(errno, std::generic_category(), "close");
    return data;
}

mode_t permissions(const std::filesystem::path& path) {
    struct stat metadata {};

    if (stat(path.c_str(), &metadata) != 0)
        throw std::system_error(errno, std::generic_category(), "stat");
    return metadata.st_mode;
}

void require_no_temporary_files(const std::filesystem::path& directory) {
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        require(
            entry.path().filename().string().find(".tmp-") == std::string::npos,
            "temporary credential file was left behind");
    }
}

void test_authority_key_matches_spec_vector() {
    TemporaryDirectory directory;
    const auto public_key_path = directory.file("authority.public");
    const std::vector<std::uint8_t> public_key{
        0x76, 0x63, 0x70, 0x00, 0x97, 0x9c, 0x1c, 0x11,
        0xaf, 0x0c, 0x30, 0x0b, 0xcd, 0x8c, 0x7f, 0xe4,
        0x86, 0x10, 0xfc, 0xe9, 0xb9, 0xc1, 0x1e, 0x3d,
        0xae, 0xe3, 0x5a, 0xe0, 0xb0, 0x8a, 0x74, 0x55,
    };
    write_file(
        public_key_path,
        public_key,
        S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

    std::array<char, SV2_CREDENTIALS_AUTHORITY_KEY_TEXT_CAPACITY> encoded{};
    require_status(
        sv2_credentials_format_authority_key(
            public_key_path.c_str(),
            encoded.data(),
            encoded.size()),
        SV2_CREDENTIALS_OK,
        "format authority key");
    require(
        std::string_view(encoded.data()) == kAuthorityKeyText,
        "authority key differs from the SV2 test vector");

    const auto short_public_key = directory.file("short.public");
    write_file(
        short_public_key,
        std::vector<std::uint8_t>(SV2_NOISE_PUBLIC_KEY_SIZE - 1u, 0u),
        S_IRUSR | S_IWUSR);
    require_status(
        sv2_credentials_format_authority_key(
            short_public_key.c_str(),
            encoded.data(),
            encoded.size()),
        SV2_CREDENTIALS_ERROR_INPUT_WRONG_SIZE,
        "reject short authority key");
}

void test_end_to_end_bundle_loads_in_runtime() {
    TemporaryDirectory directory;
    const auto authority_secret = directory.file("authority.secret");
    const auto authority_public = directory.file("authority.public");
    const auto server_secret = directory.file("server.secret");
    const auto server_public = directory.file("server.public");
    const auto bundled_authority_public = directory.file("bundle-authority.public");
    const auto certificate = directory.file("server.cert");

    require_status(
        sv2_credentials_keypair(
            authority_secret.c_str(),
            authority_public.c_str()),
        SV2_CREDENTIALS_OK,
        "generate authority keypair");
    require_status(
        sv2_credentials_keypair(
            server_secret.c_str(),
            server_public.c_str()),
        SV2_CREDENTIALS_OK,
        "generate server keypair");
    require(
        std::filesystem::file_size(authority_secret) == SV2_NOISE_SECRET_KEY_SIZE,
        "authority secret size");
    require(
        std::filesystem::file_size(server_secret) == SV2_NOISE_SECRET_KEY_SIZE,
        "server secret size");
    require(
        (permissions(authority_secret) & kPermissionMask) == kSecretPermissions,
        "authority secret permissions");
    require(
        (permissions(server_secret) & kPermissionMask) == kSecretPermissions,
        "server secret permissions");

    require_status(
        sv2_credentials_issue(
            authority_secret.c_str(),
            server_public.c_str(),
            bundled_authority_public.c_str(),
            certificate.c_str(),
            kValidFrom,
            kNotValidAfter),
        SV2_CREDENTIALS_OK,
        "issue server certificate");
    require(
        read_file(authority_public) == read_file(bundled_authority_public),
        "issued authority public key mismatch");
    require(
        std::filesystem::file_size(bundled_authority_public) ==
            SV2_NOISE_PUBLIC_KEY_SIZE,
        "bundled authority public key size");
    require(
        std::filesystem::file_size(certificate) == SV2_NOISE_CERTIFICATE_SIZE,
        "certificate size");

    const auto certificate_bytes = read_file(certificate);
    require(
        certificate_bytes[0] == 0 && certificate_bytes[1] == 0,
        "certificate version encoding");
    require(
        certificate_bytes[2] == 0xe8 && certificate_bytes[3] == 0x03,
        "valid_from encoding");
    require(
        certificate_bytes[6] == 0xd0 && certificate_bytes[7] == 0x07,
        "not_valid_after encoding");

    const auto server_secret_bytes = read_file(server_secret);
    const auto authority_public_bytes = read_file(bundled_authority_public);
    sv2_noise_credentials *raw_credentials = nullptr;
    const auto runtime_status = sv2_noise_credentials_load(
        server_secret_bytes.data(),
        server_secret_bytes.size(),
        authority_public_bytes.data(),
        authority_public_bytes.size(),
        certificate_bytes.data(),
        certificate_bytes.size(),
        kValidNow,
        &raw_credentials);
    require(runtime_status == SV2_NOISE_OK, "runtime rejected generated credentials");
    require(raw_credentials != nullptr, "runtime credential handle missing");
    sv2_noise_credentials_free(raw_credentials);

    const auto second_server_public = directory.file("server-second.public");
    require_status(
        sv2_credentials_keypair(
            server_secret.c_str(),
            second_server_public.c_str()),
        SV2_CREDENTIALS_OK,
        "reuse existing server secret");
    require(
        read_file(server_public) == read_file(second_server_public),
        "existing secret derived a different public key");
    require_no_temporary_files(directory.path());
}

void test_refuses_unsafe_inputs_and_overwrites() {
    TemporaryDirectory directory;
    const auto authority_secret = directory.file("authority.secret");
    const auto authority_public = directory.file("authority.public");
    const auto server_secret = directory.file("server.secret");
    const auto server_public = directory.file("server.public");

    require_status(
        sv2_credentials_keypair(
            authority_secret.c_str(),
            authority_public.c_str()),
        SV2_CREDENTIALS_OK,
        "generate authority keypair");
    require_status(
        sv2_credentials_keypair(
            server_secret.c_str(),
            server_public.c_str()),
        SV2_CREDENTIALS_OK,
        "generate server keypair");

    const auto invalid_authority_output = directory.file("invalid-authority.public");
    const auto invalid_certificate = directory.file("invalid.cert");
    require_status(
        sv2_credentials_issue(
            authority_secret.c_str(),
            server_public.c_str(),
            invalid_authority_output.c_str(),
            invalid_certificate.c_str(),
            kValidNow,
            kValidNow),
        SV2_CREDENTIALS_ERROR_INVALID_VALIDITY,
        "reject empty validity interval");
    require(!std::filesystem::exists(invalid_authority_output), "invalid authority output created");
    require(!std::filesystem::exists(invalid_certificate), "invalid certificate created");

    const auto existing_output = directory.file("existing.public");
    write_file(existing_output, {0x5a}, S_IRUSR | S_IWUSR);
    require_status(
        sv2_credentials_issue(
            authority_secret.c_str(),
            server_public.c_str(),
            existing_output.c_str(),
            invalid_certificate.c_str(),
            kValidFrom,
            kNotValidAfter),
        SV2_CREDENTIALS_ERROR_OUTPUT_EXISTS,
        "refuse certificate output overwrite");
    require(
        read_file(existing_output) == std::vector<std::uint8_t>{0x5a},
        "existing output changed");
    require(!std::filesystem::exists(invalid_certificate), "certificate created after overwrite");

    const auto uncreated_secret = directory.file("uncreated.secret");
    require_status(
        sv2_credentials_keypair(
            uncreated_secret.c_str(),
            existing_output.c_str()),
        SV2_CREDENTIALS_ERROR_OUTPUT_EXISTS,
        "refuse keypair output overwrite");
    require(!std::filesystem::exists(uncreated_secret), "secret created before overwrite check");

    const auto insecure_secret = directory.file("insecure.secret");
    write_file(
        insecure_secret,
        read_file(authority_secret),
        S_IRUSR | S_IWUSR | S_IRGRP);
    const auto insecure_public = directory.file("insecure.public");
    require_status(
        sv2_credentials_keypair(
            insecure_secret.c_str(),
            insecure_public.c_str()),
        SV2_CREDENTIALS_ERROR_SECRET_PERMISSIONS,
        "reject insecure secret permissions");
    require(!std::filesystem::exists(insecure_public), "public key created from insecure secret");

    const auto short_secret = directory.file("short.secret");
    write_file(short_secret, std::vector<std::uint8_t>(31, 1), S_IRUSR | S_IWUSR);
    const auto short_public = directory.file("short.public");
    require_status(
        sv2_credentials_keypair(
            short_secret.c_str(),
            short_public.c_str()),
        SV2_CREDENTIALS_ERROR_INPUT_WRONG_SIZE,
        "reject short secret");

    const auto invalid_server_public = directory.file("invalid-server.public");
    write_file(
        invalid_server_public,
        std::vector<std::uint8_t>(SV2_NOISE_PUBLIC_KEY_SIZE, 0xff),
        S_IRUSR | S_IWUSR);
    require_status(
        sv2_credentials_issue(
            authority_secret.c_str(),
            invalid_server_public.c_str(),
            invalid_authority_output.c_str(),
            invalid_certificate.c_str(),
            kValidFrom,
            kNotValidAfter),
        SV2_CREDENTIALS_ERROR_INVALID_PUBLIC_KEY,
        "reject invalid server public key");

    require_status(
        sv2_credentials_issue(
            authority_secret.c_str(),
            authority_public.c_str(),
            invalid_authority_output.c_str(),
            invalid_certificate.c_str(),
            kValidFrom,
            kNotValidAfter),
        SV2_CREDENTIALS_ERROR_KEY_REUSE,
        "reject authority key reuse as server key");
    require_no_temporary_files(directory.path());
}

} // namespace

int main() {
    const std::array<std::pair<std::string_view, std::function<void()>>, 3> tests{{
        {"authority key matches SV2 test vector", test_authority_key_matches_spec_vector},
        {"end-to-end bundle loads in runtime", test_end_to_end_bundle_loads_in_runtime},
        {"unsafe inputs and overwrites are refused", test_refuses_unsafe_inputs_and_overwrites},
    }};
    std::size_t failures = 0;

    for (const auto& [name, test] : tests) {
        try {
            test();
            std::cout << "PASS " << name << '\n';
        } catch (const std::exception& error) {
            ++failures;
            std::cerr << "FAIL " << name << ": " << error.what() << '\n';
        }
    }
    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cout << tests.size() << " tests passed\n";
    return 0;
}
