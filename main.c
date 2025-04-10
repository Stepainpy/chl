#include "chl.h"
#include <string.h>
#include <stdbool.h>

__attribute__((unused)) static void memdump(
    const void* src, size_t count, FILE* file, bool rev) {
    const uint8_t* p = (const uint8_t*)src;
    if (rev) {
        p += count;
        while (count --> 0) fprintf(file, "%02x", *--p);
    } else {
        while (count --> 0) fprintf(file, "%02x", *p++);
    }
}

__attribute__((unused)) static void memdumps(
    const void* src, size_t count, char* str, bool rev) {
    const uint8_t* p = (const uint8_t*)src;
    if (rev) {
        p += count;
        while (count --> 0) {
            sprintf(str, "%02x", *--p);
            str += 2;
        }
    } else {
        while (count --> 0) {
            sprintf(str, "%02x", *p++);
            str += 2;
        }
    }
}

#define COMMA ,
#define SELECT_3(_1, _2, _3, x, ...) x
#define HASTHREE(...) SELECT_3(__VA_ARGS__, 1, 0, 0, 0)

#define IF0(...)
#define IF1(...) __VA_ARGS__
#define IFc(c, ...) IF##c(__VA_ARGS__)
#define IF(c, ...) IFc(c, __VA_ARGS__)

int main(void) {
    FILE* textf = fopen("text.txt", "rb");
    if (!textf) return 1;

// Create hashes
#if 0
#define DO(name, ...) do {                                       \
    fputs("Create "#name" hash ... ", stdout);                   \
    FILE* fd = fopen("hash/"#name".txt", "wb");                  \
    if (!fd) { printf("error\n"); break; } rewind(textf);        \
    CHLN_RET_T(name) hash = CHLN_FUNC(name, calc_file)(textf     \
        IF(HASTHREE(__VA_ARGS__), COMMA (CHLN_KEY_T(name)){0})); \
    memdump((void*)&hash, sizeof hash, fd, sizeof hash <= 8);    \
    puts("\x1b[32mok\x1b[0m"); fclose(fd);                       \
} while (0);
    CHL_LIST_OF_NAMES
    CHL_LIST_OF_NAMES_WITH_KEY
#undef DO
#endif

// Check hashes
#if 1
#define DO(name, ...) do {                                         \
    fputs("Check "#name" hash ... ", stdout);                      \
    FILE* fd = fopen("hash/"#name".txt", "rb");                    \
    if (!fd) { puts("\x1b[34mnot found\x1b[0m"); break; }          \
    rewind(textf);                                                 \
    CHLN_RET_T(name) hash = CHLN_FUNC(name, calc_file)(textf       \
        IF(HASTHREE(__VA_ARGS__), COMMA (CHLN_KEY_T(name)){0}));   \
    char buffer [sizeof hash * 2 + 1] = {0};                       \
    char correct[sizeof hash * 2 + 1] = {0};                       \
    fread(correct, sizeof hash * 2, 1, fd); fclose(fd);            \
    memdumps((void*)&hash, sizeof hash, buffer, sizeof hash <= 8); \
    if (strcmp(correct, buffer) == 0) puts("\x1b[32mok\x1b[0m");   \
    else { puts("\x1b[31mmistmatch\x1b[0m");                       \
        printf("  \x1b[33mexpected\x1b[0m %s\n", correct);         \
        printf("  \x1b[33mreceived\x1b[0m %s\n", buffer);}         \
} while (0);
    CHL_LIST_OF_NAMES
    CHL_LIST_OF_NAMES_WITH_KEY
#undef DO
#endif

    fclose(textf);
}