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

    free(buffer);
    fclose(fd);
}