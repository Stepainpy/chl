#define CHL_DFLT fnv1a_64
#include <stdio.h>
#include <stdlib.h>
#include "chl.h"

#define FMT "%016llx"

int main(void) {
    FILE* fd = fopen("text.txt", "rb");
    if (!fd) return 1;

    fseek(fd, 0, SEEK_END);
    const size_t flen = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    char* buffer = malloc(flen);
    fread(buffer, 1, flen, fd);
    rewind(fd);

    printf("test: f3f9b7f5e7e47110\n");
    printf("span: "FMT"\n", chl_calc(buffer, flen));
    printf("file: "FMT"\n", chl_calc_file(fd));

    free(buffer);
    fclose(fd);
}