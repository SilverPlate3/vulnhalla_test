// tainted_tests.c - Test cases using REAL taint sources that CodeQL recognizes
// These use: argv[], read(), recv(), getenv(), fgets(stdin)
// Each query has TRUE POSITIVE and FALSE POSITIVE examples

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <pthread.h>
#include <errno.h>
#include <limits.h>

// ============================================================================
// GLOBAL VARIABLES FOR TESTS
// ============================================================================
int g_array[100];
pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

// ============================================================================
// 1. TOCTOU - Time-of-check Time-of-use (CWE-367)
// Uses: argv as tainted filename
// ============================================================================

// TRUE POSITIVE: stat() then open() on argv path
void toctou_argv_vulnerable(const char *filename) {
    struct stat st;
    if (stat(filename, &st) == 0 && S_ISREG(st.st_mode)) {
        // TOCTOU: attacker can replace file between stat and open
        int fd = open(filename, O_RDONLY);
        if (fd >= 0) {
            char buf[1024];
            read(fd, buf, sizeof(buf));
            close(fd);
        }
    }
}

// TRUE POSITIVE: access() then fopen() on tainted path
void toctou_access_vulnerable(const char *path) {
    if (access(path, R_OK) == 0) {
        // Race window: file can be swapped
        FILE *fp = fopen(path, "r");
        if (fp) {
            char line[256];
            fgets(line, sizeof(line), fp);
            fclose(fp);
        }
    }
}

// FALSE POSITIVE: Using fstat on already-opened fd
void toctou_safe_fstat(const char *filename) {
    int fd = open(filename, O_RDONLY);
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) == 0) {  // Safe: checks the opened file
            char buf[1024];
            read(fd, buf, st.st_size < 1024 ? st.st_size : 1024);
        }
        close(fd);
    }
}

// ============================================================================
// 2. UNCLEAR VALIDATION OF ARRAY INDEX (CWE-129)
// Uses: argv/atoi as tainted index
// ============================================================================

// TRUE POSITIVE: argv-controlled index, no bounds check
void array_index_argv_vulnerable(int index) {
    // index comes from atoi(argv[...])
    g_array[index] = 42;  // No bounds check!
}

// TRUE POSITIVE: Only upper bound checked (negative allowed)
void array_index_partial_check(int index) {
    if (index < 100) {  // Missing: index >= 0
        g_array[index] = 42;  // Negative index = underflow
    }
}

// FALSE POSITIVE: Full bounds check
void array_index_safe_full(int index) {
    if (index >= 0 && index < 100) {
        g_array[index] = 42;
    }
}

// FALSE POSITIVE: Unsigned with upper check
void array_index_safe_unsigned(unsigned int index) {
    if (index < 100) {  // unsigned can't be negative
        g_array[index] = 42;
    }
}

// ============================================================================
// 3. USER-CONTROLLED DATA MAY NOT BE NULL TERMINATED (CWE-170)
// Uses: read() which doesn't null-terminate
// ============================================================================

// TRUE POSITIVE: read() result used as string without termination
void null_term_read_vulnerable(int fd) {
    char buffer[256];
    ssize_t n = read(fd, buffer, sizeof(buffer));
    if (n > 0) {
        // BUG: buffer not null-terminated, strlen overreads
        printf("Got %zu bytes: %s\n", strlen(buffer), buffer);
    }
}

// TRUE POSITIVE: recv() result used as string
void null_term_recv_vulnerable(int sockfd) {
    char buffer[512];
    ssize_t n = recv(sockfd, buffer, sizeof(buffer), 0);
    if (n > 0) {
        // BUG: strdup expects null-terminated string
        char *copy = strdup(buffer);
        free(copy);
    }
}

// FALSE POSITIVE: Explicit null termination
void null_term_safe_explicit(int fd) {
    char buffer[256];
    ssize_t n = read(fd, buffer, sizeof(buffer) - 1);
    if (n > 0) {
        buffer[n] = '\0';  // Safe: explicit termination
        printf("Got: %s\n", buffer);
    }
}

// FALSE POSITIVE: Using length, not as string
void null_term_safe_length(int fd) {
    char buffer[256];
    ssize_t n = read(fd, buffer, sizeof(buffer));
    if (n > 0) {
        write(STDOUT_FILENO, buffer, n);  // Safe: explicit length
    }
}

// ============================================================================
// 4. USE OF POTENTIALLY DANGEROUS FUNCTION (CWE-676)
// Uses: gets, strcpy, sprintf
// ============================================================================

// TRUE POSITIVE: gets() is always dangerous
void dangerous_gets_vulnerable(void) {
    char buffer[64];
    gets(buffer);  // ALWAYS VULNERABLE - deprecated for reason
    puts(buffer);
}

// TRUE POSITIVE: strcpy from argv (no bounds)
void dangerous_strcpy_argv(const char *src) {
    char dest[32];
    strcpy(dest, src);  // src from argv could be > 32 chars
}

// TRUE POSITIVE: sprintf with argv
void dangerous_sprintf_argv(const char *name) {
    char msg[64];
    sprintf(msg, "Welcome, %s! Have a great day!", name);  // Can overflow
}

// FALSE POSITIVE: Safe alternatives
void dangerous_safe_strncpy(const char *src) {
    char dest[32];
    strncpy(dest, src, sizeof(dest) - 1);
    dest[sizeof(dest) - 1] = '\0';
}

void dangerous_safe_snprintf(const char *name) {
    char msg[64];
    snprintf(msg, sizeof(msg), "Welcome, %s!", name);
}

// ============================================================================
// 5. SUSPICIOUS POINTER SCALING (CWE-468)
// ============================================================================

// TRUE POSITIVE: Double scaling with sizeof
void pointer_scale_double(int *arr, int n) {
    // BUG: arr + n already scales by sizeof(int)
    // arr + n * sizeof(int) moves n*4 ints, not n ints
    int *ptr = arr + n * sizeof(int);
    *ptr = 42;  // Out of bounds
}

// TRUE POSITIVE: Scaling in loop index
void pointer_scale_loop(int *data, int count) {
    for (int i = 0; i < count; i++) {
        // BUG: double scaling
        int *p = data + i * sizeof(int);
        *p = i;
    }
}

// FALSE POSITIVE: Correct arithmetic (no sizeof)
void pointer_scale_safe(int *arr, int n) {
    int *ptr = arr + n;  // Correct: compiler handles scaling
    // ptr now points n elements past arr
}

// FALSE POSITIVE: Using char* where sizeof(char)==1
void pointer_scale_safe_char(char *buf, int offset) {
    char *p = buf + offset * sizeof(char);  // Harmless: sizeof(char)==1
    *p = 'X';
}

// ============================================================================
// 6. SUSPICIOUS ADD WITH SIZEOF (CWE-468)
// ============================================================================

// TRUE POSITIVE: sizeof(pointer) instead of buffer size
void sizeof_add_pointer(int n) {
    char *buf = malloc(n);
    if (buf) {
        // BUG: sizeof(buf) is 8 (pointer), not n
        char *end = buf + sizeof(buf);
        memset(buf, 'A', end - buf);  // Only clears 8 bytes!
        free(buf);
    }
}

// TRUE POSITIVE: sizeof on parameter array
void sizeof_add_array_param(int arr[]) {
    // BUG: sizeof(arr) is pointer size, not array size
    int *end = arr + sizeof(arr) / sizeof(int);
    for (int *p = arr; p < end; p++) {
        *p = 0;
    }
}

// FALSE POSITIVE: sizeof on actual array
void sizeof_add_safe_array(void) {
    int arr[10];
    size_t count = sizeof(arr) / sizeof(arr[0]);  // Correct: 10
    for (size_t i = 0; i < count; i++) {
        arr[i] = 0;
    }
}

// FALSE POSITIVE: Explicit size variable
void sizeof_add_safe_explicit(size_t size) {
    char *buf = malloc(size);
    if (buf) {
        memset(buf, 0, size);  // Safe: using explicit size
        free(buf);
    }
}

// ============================================================================
// 7. TYPE CONFUSION (CWE-843)
// ============================================================================

struct BaseObj {
    int type;
    char data[64];
};

struct AdminObj {
    int type;
    char data[64];
    void (*admin_func)(void);
};

// TRUE POSITIVE: Type field from tainted source
void type_confusion_tainted(void *obj, int type_from_network) {
    // BUG: trusting type from network
    if (type_from_network == 2) {
        struct AdminObj *admin = (struct AdminObj *)obj;
        admin->admin_func();  // Could call attacker-controlled address
    }
}

// TRUE POSITIVE: Cast based on recv'd data
void type_confusion_recv(int sockfd, void *obj) {
    int type;
    recv(sockfd, &type, sizeof(type), 0);  // Type from network
    if (type == 1) {
        struct AdminObj *a = (struct AdminObj *)obj;
        if (a->admin_func) a->admin_func();  // Dangerous
    }
}

// FALSE POSITIVE: Type set locally
void type_confusion_safe_local(struct BaseObj *obj) {
    static int verified_type = 0;  // Set by trusted code
    if (verified_type == 2) {
        struct AdminObj *admin = (struct AdminObj *)obj;
        printf("Admin data: %s\n", admin->data);
    }
}

// ============================================================================
// 8. MUTEX LOCKED TWICE (CWE-764)
// ============================================================================

static pthread_mutex_t mtx_a = PTHREAD_MUTEX_INITIALIZER;

// TRUE POSITIVE: Same mutex locked twice
void mutex_double_lock(void) {
    pthread_mutex_lock(&mtx_a);
    // ... code ...
    pthread_mutex_lock(&mtx_a);  // DEADLOCK
    pthread_mutex_unlock(&mtx_a);
    pthread_mutex_unlock(&mtx_a);
}

// TRUE POSITIVE: Conditional double lock
void mutex_conditional_double(int flag) {
    pthread_mutex_lock(&mtx_a);
    if (flag) {
        pthread_mutex_lock(&mtx_a);  // Double lock when flag true
    }
    pthread_mutex_unlock(&mtx_a);
}

// FALSE POSITIVE: Different mutexes
static pthread_mutex_t mtx_b = PTHREAD_MUTEX_INITIALIZER;

void mutex_different_safe(void) {
    pthread_mutex_lock(&mtx_a);
    pthread_mutex_lock(&mtx_b);  // Safe: different mutex
    pthread_mutex_unlock(&mtx_b);
    pthread_mutex_unlock(&mtx_a);
}

// ============================================================================
// 9. LOCK MAY NOT BE RELEASED (CWE-764)
// ============================================================================

// TRUE POSITIVE: Early return without unlock
int lock_not_released_return(int *data) {
    pthread_mutex_lock(&g_mutex);
    if (data == NULL) {
        return -1;  // BUG: mutex still locked!
    }
    *data = 100;
    pthread_mutex_unlock(&g_mutex);
    return 0;
}

// TRUE POSITIVE: Error branch missing unlock
void lock_not_released_error(int fd) {
    pthread_mutex_lock(&g_mutex);
    char buf[64];
    if (read(fd, buf, sizeof(buf)) < 0) {
        perror("read");
        return;  // BUG: mutex locked
    }
    pthread_mutex_unlock(&g_mutex);
}

// FALSE POSITIVE: All paths unlock
int lock_released_all_paths(int *data) {
    pthread_mutex_lock(&g_mutex);
    if (data == NULL) {
        pthread_mutex_unlock(&g_mutex);  // Proper cleanup
        return -1;
    }
    *data = 100;
    pthread_mutex_unlock(&g_mutex);
    return 0;
}

// FALSE POSITIVE: Cleanup via goto
int lock_released_goto(int *data, int fd) {
    int ret = -1;
    pthread_mutex_lock(&g_mutex);
    
    if (data == NULL) goto out;
    if (fd < 0) goto out;
    
    *data = fd;
    ret = 0;
    
out:
    pthread_mutex_unlock(&g_mutex);  // Always reached
    return ret;
}

// ============================================================================
// 10. UNCONTROLLED DATA USED IN PATH EXPRESSION (CWE-022)
// Uses: argv, getenv as tainted path
// ============================================================================

// TRUE POSITIVE: argv used directly in path
void path_traversal_argv(const char *user_file) {
    char path[512];
    snprintf(path, sizeof(path), "/var/data/%s", user_file);
    // BUG: user_file could be "../../../etc/passwd"
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        char buf[256];
        read(fd, buf, sizeof(buf));
        close(fd);
    }
}

// TRUE POSITIVE: getenv in path
void path_traversal_env(void) {
    char *user_dir = getenv("USER_DIR");  // Attacker controls env
    if (user_dir) {
        char path[512];
        snprintf(path, sizeof(path), "/data/%s/config", user_dir);
        FILE *fp = fopen(path, "r");  // Path traversal possible
        if (fp) fclose(fp);
    }
}

// TRUE POSITIVE: recv'd filename
void path_traversal_recv(int sockfd) {
    char filename[256];
    ssize_t n = recv(sockfd, filename, sizeof(filename) - 1, 0);
    if (n > 0) {
        filename[n] = '\0';
        unlink(filename);  // BUG: can delete any file
    }
}

// FALSE POSITIVE: basename extraction
void path_traversal_safe_basename(const char *user_file) {
    const char *base = strrchr(user_file, '/');
    base = base ? base + 1 : user_file;
    
    char path[512];
    snprintf(path, sizeof(path), "/var/data/%s", base);
    // Safe: only filename, no directory components
    FILE *fp = fopen(path, "r");
    if (fp) fclose(fp);
}

// FALSE POSITIVE: Explicit validation
void path_traversal_safe_validate(const char *user_file) {
    if (strstr(user_file, "..")) return;  // Block traversal
    if (strchr(user_file, '/')) return;   // Block subdirs
    
    char path[512];
    snprintf(path, sizeof(path), "/var/data/%s", user_file);
    FILE *fp = fopen(path, "r");
    if (fp) fclose(fp);
}

// ============================================================================
// 11. NO SPACE FOR ZERO TERMINATOR (CWE-131)
// ============================================================================

// TRUE POSITIVE: strlen without +1 for terminator
char *no_space_strlen(const char *src) {
    size_t len = strlen(src);     // Missing: +1 for '\0'
    char *copy = malloc(len);     // One byte short!
    if (copy) {
        strcpy(copy, src);        // Writes '\0' out of bounds
    }
    return copy;
}

// TRUE POSITIVE: Concat without space for terminator
char *no_space_concat(const char *a, const char *b) {
    size_t len = strlen(a) + strlen(b);  // Missing +1
    char *result = malloc(len);
    if (result) {
        strcpy(result, a);
        strcat(result, b);  // Out of bounds write
    }
    return result;
}

// FALSE POSITIVE: Proper allocation
char *space_safe_alloc(const char *src) {
    size_t len = strlen(src) + 1;  // Correct: includes '\0'
    char *copy = malloc(len);
    if (copy) {
        strcpy(copy, src);
    }
    return copy;
}

// FALSE POSITIVE: strdup handles it
char *space_safe_strdup(const char *src) {
    return strdup(src);  // strdup allocates correctly
}

// ============================================================================
// 12. UNTRUSTED INPUT FOR A CONDITION (CWE-807)
// Uses: network data for security decisions
// ============================================================================

struct UserRecord {
    int is_admin;
    char name[32];
};

// TRUE POSITIVE: Security decision from network data
void tainted_cond_network(int sockfd) {
    struct UserRecord user;
    recv(sockfd, &user, sizeof(user), 0);  // User struct from network
    
    // BUG: trusting is_admin from untrusted source
    if (user.is_admin) {
        system("cat /etc/shadow");  // Privileged operation
    }
}

// TRUE POSITIVE: Auth result from network
void tainted_cond_auth_network(int sockfd) {
    int auth_ok;
    recv(sockfd, &auth_ok, sizeof(auth_ok), 0);
    
    // BUG: auth decision from attacker-controlled data
    if (auth_ok == 1) {
        printf("Access granted!\n");
        // ... privileged operations ...
    }
}

// FALSE POSITIVE: Local comparison
void tainted_cond_safe_local(const char *password) {
    const char *correct = "hunter2";
    // Safe: comparison done locally
    if (strcmp(password, correct) == 0) {
        printf("Welcome!\n");
    }
}

// FALSE POSITIVE: Verified through internal function
extern int verify_user_internal(int user_id);

void tainted_cond_safe_verified(int user_id) {
    // Safe: verification done by trusted internal function
    if (verify_user_internal(user_id)) {
        printf("Verified user\n");
    }
}

// ============================================================================
// 13. CALL TO MEMSET MAY BE DELETED (CWE-014)
// ============================================================================

// TRUE POSITIVE: memset before free (may be optimized out)
void memset_deleted_free(void) {
    char *secret = malloc(64);
    if (secret) {
        strcpy(secret, "password123");
        // ... use secret ...
        
        // BUG: Compiler may optimize this out
        memset(secret, 0, 64);
        free(secret);  // Secret may remain in memory
    }
}

// TRUE POSITIVE: memset on stack before return
void memset_deleted_stack(void) {
    char key[32] = "encryption_key_here";
    // ... use key ...
    
    // BUG: May be optimized out (dead store before return)
    memset(key, 0, sizeof(key));
}

// FALSE POSITIVE: Using volatile
void memset_safe_volatile(void) {
    char *secret = malloc(64);
    if (secret) {
        strcpy(secret, "password123");
        
        // Safe: volatile prevents optimization
        volatile char *vs = (volatile char *)secret;
        for (int i = 0; i < 64; i++) {
            vs[i] = 0;
        }
        free(secret);
    }
}

// FALSE POSITIVE: Using explicit_bzero
void memset_safe_explicit_bzero(void) {
    char *secret = malloc(64);
    if (secret) {
        strcpy(secret, "password123");
        explicit_bzero(secret, 64);  // Cannot be optimized out
        free(secret);
    }
}

// ============================================================================
// 14. UNTERMINATED VARIADIC CALL (CWE-121)
// ============================================================================

// TRUE POSITIVE: execl without NULL
void variadic_execl_missing_null(const char *script) {
    // BUG: Missing NULL terminator
    execl("/bin/sh", "sh", "-c", script);
}

// TRUE POSITIVE: execlp without NULL
void variadic_execlp_missing_null(void) {
    // BUG: Missing NULL
    execlp("echo", "echo", "hello", "world");
}

// FALSE POSITIVE: Properly terminated
void variadic_execl_safe(const char *script) {
    execl("/bin/sh", "sh", "-c", script, (char *)NULL);  // Correct
}

// FALSE POSITIVE: NULL at end
void variadic_execlp_safe(void) {
    execlp("echo", "echo", "hello", "world", NULL);  // Correct
}

// ============================================================================
// 15. UNSIGNED DIFFERENCE EXPRESSION COMPARED TO ZERO (CWE-191)
// ============================================================================

// TRUE POSITIVE: Unsigned subtraction compared < 0 (always false)
int unsigned_diff_less_zero(unsigned int a, unsigned int b) {
    // BUG: a - b is unsigned, can never be < 0
    // This comparison is always false!
    if (a - b < 0) {
        return -1;  // Never reached
    }
    return a - b;
}

// TRUE POSITIVE: Loop with unsigned underflow
void unsigned_diff_loop(unsigned int start, unsigned int count) {
    // BUG: if start < count, wraps to huge number
    for (unsigned int i = 0; i < start - count; i++) {
        printf("%u\n", i);  // May print billions of numbers
    }
}

// TRUE POSITIVE: Size underflow
void unsigned_diff_size(unsigned int total, unsigned int used) {
    // BUG: if used > total, wraps to ~4GB
    size_t remaining = total - used;
    char *buf = malloc(remaining);  // Huge allocation
    free(buf);
}

// FALSE POSITIVE: Check before subtraction
int unsigned_diff_safe_check(unsigned int a, unsigned int b) {
    if (a < b) {
        return -1;  // Handle underflow case
    }
    return a - b;  // Safe: a >= b
}

// FALSE POSITIVE: Using signed types
int signed_diff_safe(int a, int b) {
    // Safe: signed can be negative
    if (a - b < 0) {
        return -1;
    }
    return a - b;
}

// ============================================================================
// MAIN - Uses argv to create taint flow
// ============================================================================

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <filename> <index>\n", argv[0]);
        return 1;
    }
    
    // 1. TOCTOU - tainted filename from argv
    toctou_argv_vulnerable(argv[1]);
    toctou_access_vulnerable(argv[1]);
    
    // 2. Array index - tainted from argv
    int index = atoi(argv[2]);
    array_index_argv_vulnerable(index);
    array_index_partial_check(index);
    
    // 4. Dangerous functions - tainted from argv
    dangerous_strcpy_argv(argv[1]);
    dangerous_sprintf_argv(argv[1]);
    
    // 10. Path traversal - tainted from argv
    path_traversal_argv(argv[1]);
    
    // 11. No space for terminator - tainted from argv
    char *copy = no_space_strlen(argv[1]);
    free(copy);
    
    // 15. Unsigned diff
    unsigned int a = (unsigned int)atoi(argv[2]);
    unsigned int b = 100;
    unsigned_diff_less_zero(a, b);
    
    // Gets (always vulnerable, no taint needed)
    dangerous_gets_vulnerable();
    
    printf("Tests executed\n");
    return 0;
}
