#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void command_injection(char *user_input) {
    char cmd[256];
    sprintf(cmd, "echo %s", user_input);
    system(cmd);
}

void buffer_overflow(char *src) {
    char dest[10];
    strcpy(dest, src);
}

void format_string(char *user_input) {
    printf(user_input);
}

void copy_source_size(char *src, size_t src_len) {
    char dest[10];
    memcpy(dest, src, src_len);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        command_injection(argv[1]);
        buffer_overflow(argv[1]);
        format_string(argv[1]);
        copy_source_size(argv[1], strlen(argv[1]));
    }
    return 0;
}
