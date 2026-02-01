// trigger_missing_queries.c - Direct patterns to trigger 13 missing CodeQL queries
// Updated with direct taint flows in main()

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/types.h>

// ============================================================================
// EASY QUERIES (5)
// ============================================================================

// 1. Mutex locked twice (Mutex locked twice.ql)
pthread_mutex_t global_mutex = PTHREAD_MUTEX_INITIALIZER;

void trigger_mutex_locked_twice(void) {
    pthread_mutex_lock(&global_mutex);
    pthread_mutex_lock(&global_mutex);  // Direct double lock
    pthread_mutex_unlock(&global_mutex);
    pthread_mutex_unlock(&global_mutex);
}

// 2. Unterminated variadic call - needs 80% of calls to have terminator
void setup_variadic_pattern(void) {
    // Establish pattern: 5 good calls
    execl("/bin/echo", "echo", "a", (char*)0);
    execl("/bin/echo", "echo", "b", (char*)0);
    execl("/bin/echo", "echo", "c", (char*)0);  
    execl("/bin/echo", "echo", "d", (char*)0);
    execl("/bin/echo", "echo", "e", (char*)0);
    // 1 bad call - missing terminator
    execl("/bin/echo", "echo", "MISSING");
}

// 3. Unsigned diff - need clean pattern
unsigned int trigger_unsigned_diff(unsigned int a, unsigned int b) {
    if (a - b < 0) {  // Always false for unsigned
        return 0;
    }
    return a - b;
}

// 4. memset may be deleted - need no subsequent use after memset
void trigger_memset_deleted(void) {
    char password[64];
    strcpy(password, "secret");
    printf("Using: %s\n", password);
    memset(password, 0, sizeof(password));
    // No use of password after memset
}

// 5. Conditionally uninitialized - scanf pattern
void trigger_conditionally_uninit(void) {
    int value;
    scanf("%d", &value);  // Return not checked, value may be uninitialized
    printf("Value: %d\n", value);
}

// ============================================================================
// MEDIUM QUERIES - Helper functions
// ============================================================================

// 13. Use of potentially dangerous function (thread-unsafe)
void trigger_dangerous_functions(void) {
    time_t t = time(NULL);
    struct tm *gm = gmtime(&t);      // Thread-unsafe
    struct tm *loc = localtime(&t);   // Thread-unsafe
    char *ct = ctime(&t);             // Thread-unsafe
    char *asc = asctime(loc);         // Thread-unsafe
    printf("%d %d %s %s\n", gm->tm_year, loc->tm_hour, ct, asc);
}

// Global array for index tests
int g_array[100];

// ============================================================================
// MAIN - Direct taint flows from argv (no intermediate functions)
// ============================================================================

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }

    // ========================================
    // EASY queries - no taint needed
    // ========================================
    
    // 1. Mutex locked twice
    trigger_mutex_locked_twice();
    
    // 2. Unterminated variadic
    setup_variadic_pattern();
    
    // 3. Unsigned diff
    unsigned int ua = 10, ub = 20;
    if (ua - ub < 0) {  // Direct unsigned comparison
        printf("negative\n");
    }
    
    // 4. memset deleted
    trigger_memset_deleted();
    
    // 5. Conditionally uninit
    trigger_conditionally_uninit();
    
    // 13. Dangerous functions
    trigger_dangerous_functions();

    // ========================================
    // MEDIUM queries - DIRECT taint from argv
    // ========================================
    
    // 6. Command line injection - sprintf + system
    {
        char cmd[256];
        sprintf(cmd, "echo %s", argv[1]);  // Concatenation
        system(cmd);  // Sink
    }
    
    // 7. Uncontrolled format string - direct printf
    {
        printf(argv[1]);  // Direct format string from argv
        fprintf(stderr, argv[1]);
    }
    
    // 8. Tainted allocation size - direct malloc
    {
        int size = atoi(argv[1]);
        char *buf = malloc(size);  // Direct tainted alloc
        if (buf) {
            memset(buf, 0, size);
            free(buf);
        }
    }
    
    // 9. Unclear array index - direct array access
    {
        int idx = atoi(argv[1]);
        g_array[idx] = 42;  // Direct tainted index, no bounds check
    }
    
    // 10. Untrusted input for condition - privilege escalation
    {
        int is_admin = atoi(argv[1]);
        if (is_admin) {
            setuid(0);  // Privilege escalation based on tainted condition
        }
    }
    
    // 11. Copy using source size - strlen on argv
    {
        char dest[32];
        size_t len = strlen(argv[1]);
        memcpy(dest, argv[1], len);  // Using source size
    }
    
    // 12. Suspicious pointer scaling - double scale
    {
        int *arr = g_array;
        int offset = atoi(argv[1]);
        int *ptr = arr + offset * sizeof(int);  // Double scaling
        *ptr = 99;
    }
    
    // Alternative patterns for harder queries:
    
    // Try read() as taint source for format string
    {
        char buf[256];
        ssize_t n = read(STDIN_FILENO, buf, sizeof(buf)-1);
        if (n > 0) {
            buf[n] = '\0';
            printf(buf);  // Format string from read()
        }
    }
    
    // Try environment variable for taint
    {
        char *env_val = getenv("USER_INPUT");
        if (env_val) {
            int idx = atoi(env_val);
            g_array[idx] = 1;  // Array index from env
            
            char cmd[256];
            sprintf(cmd, "cat %s", env_val);
            system(cmd);  // Command injection from env
            
            printf(env_val);  // Format string from env
            
            if (atoi(env_val) == 1) {
                setuid(0);  // Privilege based on env
            }
        }
    }
    
    // File descriptor taint source
    {
        char input[128];
        if (fgets(input, sizeof(input), stdin)) {
            int idx = atoi(input);
            g_array[idx] = 2;  // Array from stdin
            
            printf(input);  // Format string from stdin
            
            char cmd[256];
            sprintf(cmd, "ls %s", input);
            system(cmd);  // Command injection from stdin
        }
    }

    return 0;
}
