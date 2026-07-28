#include "credentials.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_usage(const char *program) {
    fprintf(
        stderr,
        "Usage:\n"
        "  %s keypair SECRET_FILE PUBLIC_FILE\n"
        "  %s print-authority-key PUBLIC_FILE\n"
        "  %s issue AUTHORITY_SECRET SERVER_PUBLIC AUTHORITY_PUBLIC_OUT "
        "CERTIFICATE_OUT VALID_FROM NOT_VALID_AFTER\n",
        program,
        program,
        program);
}

static bool parse_timestamp(const char *text, uint32_t *timestamp) {
    char *end = NULL;
    unsigned long long value;

    if (text == NULL || text[0] == '\0')
        return false;
    for (const char *cursor = text; *cursor != '\0'; ++cursor) {
        if (*cursor < '0' || *cursor > '9')
            return false;
    }
    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value > UINT32_MAX)
        return false;
    *timestamp = (uint32_t)value;
    return true;
}

int main(int argc, char **argv) {
    sv2_credentials_status status;

    if (argc == 4 && strcmp(argv[1], "keypair") == 0) {
        status = sv2_credentials_keypair(argv[2], argv[3]);
    } else if (argc == 3 && strcmp(argv[1], "print-authority-key") == 0) {
        char authority_key[SV2_CREDENTIALS_AUTHORITY_KEY_TEXT_CAPACITY];

        status = sv2_credentials_format_authority_key(
            argv[2],
            authority_key,
            sizeof(authority_key));
        if (status == SV2_CREDENTIALS_OK &&
            (printf("%s\n", authority_key) < 0 || fflush(stdout) != 0)) {
            fprintf(stderr, "error: failed to write authority key\n");
            return 1;
        }
    } else if (argc == 8 && strcmp(argv[1], "issue") == 0) {
        uint32_t valid_from;
        uint32_t not_valid_after;

        if (!parse_timestamp(argv[6], &valid_from) ||
            !parse_timestamp(argv[7], &not_valid_after)) {
            fprintf(stderr, "error: timestamps must be decimal U32 values\n");
            return 2;
        }
        status = sv2_credentials_issue(
            argv[2],
            argv[3],
            argv[4],
            argv[5],
            valid_from,
            not_valid_after);
    } else {
        print_usage(argv[0]);
        return 2;
    }

    if (status != SV2_CREDENTIALS_OK) {
        fprintf(stderr, "error: %s\n", sv2_credentials_status_string(status));
        return 1;
    }
    return 0;
}
