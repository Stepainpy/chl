#define CHL_DEFAULT sha1
#include <stdio.h>
#include <stdlib.h>
#include "chl.h"

void memdump(const void* src, size_t count, FILE* file) {
    const uint8_t* p = (const uint8_t*)src;
    while (count --> 0) fprintf(file, "%02x", *p++);
}

#define CORRECT_HASH "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
#if 0 // integer branch
#define FMT "%016llx"
#define puth(rem, hr) printf(rem": "FMT"\n", hr)
#else // array branch
#define puth(rem, hr) do { \
    printf(rem": "); \
    memdump((hr).array, \
        sizeof (hr).array, \
        stdout); \
    putchar('\n'); \
} while (0);
#endif

uint8_t hexd2nib(char nib) {
    if ('0' <= nib && nib <= '9')
        return nib - '0';
    if ('a' <= nib && nib <= 'f')
        return nib - 'a' + 10;
    return 0;
}

void check_hash(chl_ret_t* got) {
    const size_t sz = sizeof *got;
    uint8_t corp[sizeof *got] = {0};
    for (size_t i = 0; i < sz; i++)
        corp[i] =
            hexd2nib(CORRECT_HASH[2 * i]) << 4 |
            hexd2nib(CORRECT_HASH[2 * i + 1]);

    uint8_t* cp = corp, *gp = (uint8_t*)got;
    size_t match = 0;
    for (size_t i = 0; i < sz; i++)
        if (*cp++ == *gp++) ++match;

    if (match == sz)
        printf("\x1b[32mFull match\x1b[0m (%zu/%zu)\n", sz, sz);
    else
        printf("\x1b[31mIncomplete match\x1b[0m (%zu/%zu)\n", match, sz);
}

int main(void) {
    FILE* fd = fopen("text.txt", "rb");
    if (!fd) return 1;

    fseek(fd, 0, SEEK_END);
    const size_t flen = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    char* buffer = malloc(flen);
    fread(buffer, 1, flen, fd);
    rewind(fd);

    chl_ret_t span_hash = chl_calc_span(buffer, flen);
    chl_ret_t file_hash = chl_calc_file(fd);

    puts("test: "CORRECT_HASH);
    puth("span", span_hash);
    puth("file", file_hash);
    check_hash(&span_hash);

    free(buffer);
    fclose(fd);
}