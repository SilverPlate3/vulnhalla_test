// direct_taint_tests.c - Ultra-direct taint patterns for CodeQL
// Each pattern uses the SIMPLEST possible flow from source to sink

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// ============================================================================
// COMMAND LINE INJECTION - sprintf then system
// ============================================================================

void cmd_injection_sprintf(void) {
    char input[256];
    char cmd[512];
    
    // Source: fgets from stdin
    if (fgets(input, sizeof(input), stdin)) {
        // Concatenation with sprintf
        sprintf(cmd, "echo '%s'", input);
        // Sink: system
        system(cmd);
    }
}

void cmd_injection_snprintf(void) {
    char *env = getenv("CMD_INPUT");
    if (env) {
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "ls %s", env);
        system(cmd);
    }
}

// ============================================================================
// UNCONTROLLED FORMAT STRING - direct printf
// ============================================================================

void format_string_fgets(void) {
    char fmt[256];
    if (fgets(fmt, sizeof(fmt), stdin)) {
        printf(fmt);  // Direct format string vulnerability
    }
}

void format_string_getenv(void) {
    char *fmt = getenv("FMT_STRING");
    if (fmt) {
        printf(fmt);  // Format string from env
    }
}

void format_string_read(void) {
    char buf[256];
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        fprintf(stderr, buf);  // Format string from read
    }
}

// ============================================================================
// TAINTED ALLOCATION SIZE
// ============================================================================

void tainted_alloc_fgets(void) {
    char input[32];
    if (fgets(input, sizeof(input), stdin)) {
        size_t size = strtoul(input, NULL, 10);
        char *buf = malloc(size);  // Tainted allocation
        if (buf) {
            memset(buf, 0, size);
            free(buf);
        }
    }
}

void tainted_alloc_getenv(void) {
    char *size_str = getenv("ALLOC_SIZE");
    if (size_str) {
        size_t size = atoi(size_str);
        char *buf = malloc(size);  // Tainted from env
        free(buf);
    }
}

// ============================================================================
// UNCLEAR ARRAY INDEX VALIDATION
// ============================================================================

int g_arr[100];

void array_index_fgets(void) {
    char input[32];
    if (fgets(input, sizeof(input), stdin)) {
        int idx = atoi(input);
        g_arr[idx] = 1;  // No bounds check
    }
}

void array_index_getenv(void) {
    char *idx_str = getenv("ARRAY_INDEX");
    if (idx_str) {
        int idx = atoi(idx_str);
        g_arr[idx] = 2;  // No bounds check
    }
}

// ============================================================================
// UNTRUSTED INPUT FOR A CONDITION
// ============================================================================

void untrusted_cond_fgets(void) {
    char input[32];
    if (fgets(input, sizeof(input), stdin)) {
        int is_admin = atoi(input);
        if (is_admin) {
            setuid(0);  // Privilege escalation
        }
    }
}

void untrusted_cond_getenv(void) {
    char *level = getenv("AUTH_LEVEL");
    if (level) {
        if (atoi(level) >= 2) {
            setuid(0);  // Privilege based on env
        }
    }
}

// ============================================================================
// COPY FUNCTION USING SOURCE SIZE
// Pattern: memcpy(dest, src, strlen(src)) where src is tainted
// ============================================================================

void copy_source_size_fgets(void) {
    char src[1024];
    char dest[64];
    
    if (fgets(src, sizeof(src), stdin)) {
        // BUG: Using strlen(src) not sizeof(dest)
        memcpy(dest, src, strlen(src));
    }
}

void copy_source_size_getenv(void) {
    char dest[32];
    char *src = getenv("COPY_DATA");
    
    if (src) {
        // BUG: memcpy using source variable in size
        memcpy(dest, src, strlen(src));
    }
}

void copy_source_size_strncpy(void) {
    char dest[32];
    char src[256];
    
    if (fgets(src, sizeof(src), stdin)) {
        // BUG: strncpy using source size
        strncpy(dest, src, strlen(src));
    }
}

// ============================================================================  
// UNTRUSTED INPUT FOR A CONDITION
// Pattern: if (tainted) { raisesPrivilege(); }
// ============================================================================

void untrusted_cond_setuid(void) {
    char input[32];
    if (fgets(input, sizeof(input), stdin)) {
        int is_root = atoi(input);
        if (is_root) {
            setuid(0);  // Privilege escalation
        }
    }
}

void untrusted_cond_setgid(void) {
    char *level = getenv("PRIV_LEVEL");
    if (level && atoi(level) > 0) {
        setgid(0);  // Privilege escalation
    }
}

void untrusted_cond_system(void) {
    char input[32];
    if (fgets(input, sizeof(input), stdin)) {
        if (atoi(input) == 1) {
            system("whoami");  // System call in tainted condition
        }
    }
}

// ============================================================================
// EASY QUERY PATTERNS
// ============================================================================

// Call to memset may be deleted - stack buffer, no use after memset
void memset_deleted_stack(void) {
    char secret[64];
    strcpy(secret, "password123");
    printf("Using secret\n");
    // This memset may be deleted by compiler
    memset(secret, 0, sizeof(secret));
    // No use of secret after this point - function returns
}

// Call to memset may be deleted - heap, memset then free
void memset_deleted_heap(void) {
    char *key = malloc(32);
    if (key) {
        strcpy(key, "encryption_key");
        // Use the key
        printf("Key loaded\n");
        // Memset before free - may be deleted
        memset(key, 0, 32);
        free(key);
    }
}

// Unsigned difference compared to zero
// Need pattern: if ((unsigned)a - (unsigned)b < 0)
int unsigned_compare_zero(void) {
    unsigned int x = 5;
    unsigned int y = 10;
    // BUG: unsigned subtraction can't be < 0
    if (x - y < 0) {
        return 1;
    }
    return 0;
}

// ============================================================================
// MAIN
// ============================================================================

int main(void) {
    printf("Direct taint tests loaded\n");
    
    // Call easy query triggers
    memset_deleted_stack();
    memset_deleted_heap();
    unsigned_compare_zero();
    
    return 0;
}
