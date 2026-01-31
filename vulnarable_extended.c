// vulnarable_extended.c - Test cases for 15 new CodeQL queries
// Each section has TRUE POSITIVE (vulnerable) and FALSE POSITIVE (safe) examples

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>
#include <errno.h>

// External functions to simulate user input (prevents compiler optimization)
extern char *get_user_input(void);
extern int get_user_int(void);
extern size_t get_user_size(void);
extern char *get_user_path(void);

// ============================================================================
// 1. TOCTOU - Time-of-check Time-of-use (CWE-367)
// ============================================================================

// TRUE POSITIVE: Classic TOCTOU race condition
void toctou_vulnerable(const char *filename) {
    struct stat st;
    // Check if file exists and is regular file
    if (stat(filename, &st) == 0 && S_ISREG(st.st_mode)) {
        // TOCTOU: File could be replaced with symlink between stat and open
        int fd = open(filename, O_RDONLY);
        if (fd >= 0) {
            char buf[1024];
            read(fd, buf, sizeof(buf));
            close(fd);
        }
    }
}

// TRUE POSITIVE: Access check before open
void toctou_access_check(const char *filename) {
    // Check if user can read the file
    if (access(filename, R_OK) == 0) {
        // TOCTOU: File could be swapped between access() and fopen()
        FILE *fp = fopen(filename, "r");
        if (fp) {
            char buf[256];
            fgets(buf, sizeof(buf), fp);
            fclose(fp);
        }
    }
}

// FALSE POSITIVE: Using file descriptor throughout (safe)
void toctou_safe_fd(const char *filename) {
    int fd = open(filename, O_RDONLY);
    if (fd >= 0) {
        struct stat st;
        // Safe: fstat operates on the already-opened file descriptor
        if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
            char buf[1024];
            read(fd, buf, sizeof(buf));
        }
        close(fd);
    }
}

// FALSE POSITIVE: O_NOFOLLOW prevents symlink attack
void toctou_safe_nofollow(const char *filename) {
    struct stat st;
    if (stat(filename, &st) == 0) {
        // Safe: O_NOFOLLOW prevents symlink following
        int fd = open(filename, O_RDONLY | O_NOFOLLOW);
        if (fd >= 0) {
            char buf[1024];
            read(fd, buf, sizeof(buf));
            close(fd);
        }
    }
}

// ============================================================================
// 2. UNCLEAR VALIDATION OF ARRAY INDEX (CWE-129)
// ============================================================================

int global_array[100];

// TRUE POSITIVE: User-controlled array index without bounds check
void array_index_vulnerable(void) {
    int index = get_user_int();
    // No bounds check - attacker controls index
    global_array[index] = 42;
}

// TRUE POSITIVE: Partial bounds check (only upper bound)
void array_index_partial_check(void) {
    int index = get_user_int();
    if (index < 100) {
        // Missing check for negative index
        global_array[index] = 42;
    }
}

// FALSE POSITIVE: Proper bounds check
void array_index_safe(void) {
    int index = get_user_int();
    if (index >= 0 && index < 100) {
        global_array[index] = 42;
    }
}

// FALSE POSITIVE: Using unsigned with upper bound check
void array_index_safe_unsigned(void) {
    unsigned int index = (unsigned int)get_user_int();
    if (index < 100) {
        // Safe: unsigned can't be negative
        global_array[index] = 42;
    }
}

// ============================================================================
// 3. USER-CONTROLLED DATA MAY NOT BE NULL TERMINATED (CWE-170)
// ============================================================================

// TRUE POSITIVE: read() doesn't null-terminate, but used as string
void null_term_vulnerable(int fd) {
    char buffer[256];
    ssize_t n = read(fd, buffer, sizeof(buffer));
    if (n > 0) {
        // Bug: buffer is not null-terminated, strlen will overread
        printf("Read %zu bytes: %s\n", strlen(buffer), buffer);
    }
}

// TRUE POSITIVE: recv() without null termination
void null_term_recv_vulnerable(int sockfd) {
    char buffer[1024];
    ssize_t n = recv(sockfd, buffer, sizeof(buffer), 0);
    if (n > 0) {
        // Bug: using buffer as string without null terminator
        char *copy = strdup(buffer);
        free(copy);
    }
}

// FALSE POSITIVE: Explicit null termination after read
void null_term_safe(int fd) {
    char buffer[256];
    ssize_t n = read(fd, buffer, sizeof(buffer) - 1);
    if (n > 0) {
        buffer[n] = '\0';  // Explicit null termination
        printf("Read: %s\n", buffer);
    }
}

// FALSE POSITIVE: Using length-bounded function
void null_term_safe_bounded(int fd) {
    char buffer[256];
    ssize_t n = read(fd, buffer, sizeof(buffer));
    if (n > 0) {
        // Safe: using explicit length, not treating as string
        fwrite(buffer, 1, n, stdout);
    }
}

// ============================================================================
// 4. USE OF POTENTIALLY DANGEROUS FUNCTION (CWE-676)
// ============================================================================

// TRUE POSITIVE: gets() is always dangerous
void dangerous_gets(void) {
    char buffer[64];
    gets(buffer);  // ALWAYS VULNERABLE - no bounds checking possible
    printf("%s\n", buffer);
}

// TRUE POSITIVE: strcpy with user input
void dangerous_strcpy(void) {
    char dest[32];
    char *src = get_user_input();
    strcpy(dest, src);  // Dangerous if src > 32 bytes
}

// TRUE POSITIVE: sprintf without bounds
void dangerous_sprintf(void) {
    char buffer[64];
    char *user = get_user_input();
    sprintf(buffer, "Hello, %s! Welcome.", user);  // Can overflow
}

// FALSE POSITIVE: Using safe alternatives
void dangerous_safe_alternatives(void) {
    char buffer[64];
    char *user = get_user_input();
    
    // Safe: fgets with explicit size
    fgets(buffer, sizeof(buffer), stdin);
    
    // Safe: strncpy with size limit
    strncpy(buffer, user, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    
    // Safe: snprintf with size limit
    snprintf(buffer, sizeof(buffer), "Hello, %s!", user);
}

// ============================================================================
// 5. SUSPICIOUS POINTER SCALING (CWE-468)
// ============================================================================

// TRUE POSITIVE: Manual sizeof multiplication on typed pointer
void pointer_scaling_vulnerable(int n) {
    int *arr = malloc(n * sizeof(int));
    if (arr) {
        // Bug: pointer arithmetic already scales by sizeof(int)
        // This actually moves n*sizeof(int) ints, not n ints
        int *ptr = arr + n * sizeof(int);  // WRONG!
        *ptr = 42;  // Out of bounds write
        free(arr);
    }
}

// TRUE POSITIVE: Wrong scaling in loop
void pointer_scaling_loop_vulnerable(void) {
    int data[10];
    for (int i = 0; i < 10; i++) {
        // Bug: double scaling
        int *p = data + i * sizeof(int);  // WRONG!
        *p = i;
    }
}

// FALSE POSITIVE: Correct pointer arithmetic
void pointer_scaling_safe(int n) {
    int *arr = malloc(n * sizeof(int));
    if (arr) {
        // Correct: compiler handles scaling
        int *ptr = arr + n - 1;  // Points to last element
        *ptr = 42;
        free(arr);
    }
}

// FALSE POSITIVE: Intentional byte-level arithmetic with char*
void pointer_scaling_safe_char(void) {
    char *buffer = malloc(100);
    if (buffer) {
        // Safe: char* has scaling factor of 1
        char *p = buffer + 50 * sizeof(char);  // Equivalent to buffer + 50
        *p = 'A';
        free(buffer);
    }
}

// ============================================================================
// 6. SUSPICIOUS ADD WITH SIZEOF (CWE-468)
// ============================================================================

// TRUE POSITIVE: Adding sizeof(pointer) instead of buffer size
void sizeof_add_vulnerable(void) {
    char *buf = malloc(100);
    if (buf) {
        // Bug: sizeof(buf) is pointer size (8), not buffer size (100)
        char *end = buf + sizeof(buf);  // WRONG! end = buf + 8
        memset(buf, 0, end - buf);  // Only clears 8 bytes
        free(buf);
    }
}

// TRUE POSITIVE: sizeof in pointer arithmetic
void sizeof_add_vulnerable2(int *arr, int n) {
    // Bug: sizeof(arr) is pointer size, not array size
    int *end = arr + sizeof(arr);  // WRONG!
    while (arr < end) {
        *arr++ = 0;
    }
}

// FALSE POSITIVE: Correct use of sizeof for array
void sizeof_add_safe_array(void) {
    int arr[10];
    // Safe: sizeof(arr) gives actual array size
    size_t len = sizeof(arr) / sizeof(arr[0]);
    for (size_t i = 0; i < len; i++) {
        arr[i] = 0;
    }
}

// FALSE POSITIVE: Using separate size variable
void sizeof_add_safe_explicit(size_t size) {
    char *buf = malloc(size);
    if (buf) {
        char *end = buf + size;  // Safe: using actual size
        memset(buf, 0, end - buf);
        free(buf);
    }
}

// ============================================================================
// 7. TYPE CONFUSION (CWE-843)
// ============================================================================

struct Animal {
    int type;
    char name[32];
};

struct Dog {
    int type;
    char name[32];
    void (*bark)(void);
};

struct Cat {
    int type;
    char name[32];
    int lives;
};

// TRUE POSITIVE: Casting based on untrusted type field
void type_confusion_vulnerable(void *data) {
    struct Animal *animal = (struct Animal *)data;
    // Bug: trusting type field from potentially attacker-controlled data
    if (animal->type == 1) {
        struct Dog *dog = (struct Dog *)data;
        dog->bark();  // Could call arbitrary function if type confused
    }
}

// TRUE POSITIVE: Union type confusion
union Value {
    int as_int;
    char *as_string;
    void (*as_func)(void);
};

void type_confusion_union(union Value *v, int type) {
    // Bug: type comes from user, could mismatch actual data
    if (type == 2) {
        v->as_func();  // Calling arbitrary address if wrong type
    }
}

// FALSE POSITIVE: Type verified through trusted means
void type_confusion_safe(struct Animal *animal) {
    // Safe: type is validated internally, not from user input
    static int internal_type = 0;
    if (internal_type == 1) {
        struct Dog *dog = (struct Dog *)animal;
        printf("Dog: %s\n", dog->name);
    }
}

// FALSE POSITIVE: Safe downcast with compile-time known type
void type_confusion_safe_known(void) {
    struct Dog dog = {1, "Rex", NULL};
    struct Animal *animal = (struct Animal *)&dog;
    // Safe: we know the actual type
    printf("Animal: %s\n", animal->name);
}

// ============================================================================
// 8. MUTEX LOCKED TWICE (CWE-764)
// ============================================================================

pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex2 = PTHREAD_MUTEX_INITIALIZER;

// TRUE POSITIVE: Same mutex locked twice
void mutex_double_lock_vulnerable(void) {
    pthread_mutex_lock(&mutex1);
    // ... some code ...
    pthread_mutex_lock(&mutex1);  // DEADLOCK: same mutex locked twice
    pthread_mutex_unlock(&mutex1);
    pthread_mutex_unlock(&mutex1);
}

// TRUE POSITIVE: Conditional path leads to double lock
void mutex_double_lock_conditional(int flag) {
    pthread_mutex_lock(&mutex1);
    if (flag) {
        pthread_mutex_lock(&mutex1);  // Double lock if flag is true
    }
    pthread_mutex_unlock(&mutex1);
}

// FALSE POSITIVE: Different mutexes
void mutex_safe_different(void) {
    pthread_mutex_lock(&mutex1);
    pthread_mutex_lock(&mutex2);  // Safe: different mutex
    pthread_mutex_unlock(&mutex2);
    pthread_mutex_unlock(&mutex1);
}

// FALSE POSITIVE: Recursive mutex (allows re-locking)
void mutex_safe_recursive(void) {
    pthread_mutexattr_t attr;
    pthread_mutex_t recursive_mutex;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&recursive_mutex, &attr);
    
    pthread_mutex_lock(&recursive_mutex);
    pthread_mutex_lock(&recursive_mutex);  // Safe: recursive mutex
    pthread_mutex_unlock(&recursive_mutex);
    pthread_mutex_unlock(&recursive_mutex);
    
    pthread_mutex_destroy(&recursive_mutex);
}

// ============================================================================
// 9. LOCK MAY NOT BE RELEASED (CWE-764)
// ============================================================================

// TRUE POSITIVE: Early return without unlock
int lock_not_released_early_return(int *data) {
    pthread_mutex_lock(&mutex1);
    if (data == NULL) {
        return -1;  // Bug: mutex not released on error path
    }
    *data = 42;
    pthread_mutex_unlock(&mutex1);
    return 0;
}

// TRUE POSITIVE: Exception path misses unlock
void lock_not_released_error(int fd) {
    pthread_mutex_lock(&mutex1);
    char buf[256];
    if (read(fd, buf, sizeof(buf)) < 0) {
        perror("read failed");
        return;  // Bug: mutex not released
    }
    pthread_mutex_unlock(&mutex1);
}

// FALSE POSITIVE: All paths release lock
int lock_released_all_paths(int *data) {
    pthread_mutex_lock(&mutex1);
    if (data == NULL) {
        pthread_mutex_unlock(&mutex1);  // Proper cleanup
        return -1;
    }
    *data = 42;
    pthread_mutex_unlock(&mutex1);
    return 0;
}

// FALSE POSITIVE: Using goto for cleanup
int lock_released_goto(int *data, int fd) {
    int ret = -1;
    pthread_mutex_lock(&mutex1);
    
    if (data == NULL) goto cleanup;
    if (fd < 0) goto cleanup;
    
    *data = fd;
    ret = 0;
    
cleanup:
    pthread_mutex_unlock(&mutex1);  // Always reached
    return ret;
}

// ============================================================================
// 10. UNCONTROLLED DATA USED IN PATH EXPRESSION (CWE-022)
// ============================================================================

// TRUE POSITIVE: Direct use of user path
void path_traversal_vulnerable(void) {
    char *user_path = get_user_path();
    char full_path[512];
    snprintf(full_path, sizeof(full_path), "/var/data/%s", user_path);
    // Bug: user_path could be "../../../etc/passwd"
    FILE *fp = fopen(full_path, "r");
    if (fp) {
        char buf[1024];
        fread(buf, 1, sizeof(buf), fp);
        fclose(fp);
    }
}

// TRUE POSITIVE: Path from network
void path_traversal_network(int sockfd) {
    char filename[256];
    recv(sockfd, filename, sizeof(filename) - 1, 0);
    filename[255] = '\0';
    // Bug: filename from network could contain path traversal
    unlink(filename);  // Could delete arbitrary files
}

// FALSE POSITIVE: Basename extraction removes path components
void path_traversal_safe_basename(void) {
    char *user_path = get_user_path();
    char *base = strrchr(user_path, '/');
    if (base) base++; else base = user_path;
    
    // Also check for backslash
    char *base2 = strrchr(base, '\\');
    if (base2) base = base2 + 1;
    
    // Safe: only filename, no directory components
    char full_path[512];
    snprintf(full_path, sizeof(full_path), "/var/data/%s", base);
    FILE *fp = fopen(full_path, "r");
    if (fp) fclose(fp);
}

// FALSE POSITIVE: Validating path doesn't escape
void path_traversal_safe_validate(void) {
    char *user_path = get_user_path();
    // Check for path traversal attempts
    if (strstr(user_path, "..") != NULL) {
        return;  // Reject path traversal
    }
    if (user_path[0] == '/') {
        return;  // Reject absolute paths
    }
    
    char full_path[512];
    snprintf(full_path, sizeof(full_path), "/var/data/%s", user_path);
    FILE *fp = fopen(full_path, "r");
    if (fp) fclose(fp);
}

// ============================================================================
// 11. NO SPACE FOR ZERO TERMINATOR (CWE-131)
// ============================================================================

// TRUE POSITIVE: strlen without +1
char *no_zero_term_vulnerable(const char *src) {
    size_t len = strlen(src);  // Bug: doesn't include null terminator
    char *copy = malloc(len);  // One byte too small
    strcpy(copy, src);  // Writes null terminator out of bounds
    return copy;
}

// TRUE POSITIVE: Off-by-one in buffer calculation
void no_zero_term_concat(const char *a, const char *b) {
    size_t len = strlen(a) + strlen(b);  // Bug: missing +1
    char *result = malloc(len);
    strcpy(result, a);
    strcat(result, b);  // Out of bounds write
    printf("%s\n", result);
    free(result);
}

// FALSE POSITIVE: Proper allocation with +1
char *zero_term_safe(const char *src) {
    size_t len = strlen(src) + 1;  // Correct: includes null terminator
    char *copy = malloc(len);
    if (copy) {
        strcpy(copy, src);
    }
    return copy;
}

// FALSE POSITIVE: Using strdup (handles sizing internally)
char *zero_term_safe_strdup(const char *src) {
    return strdup(src);  // Safe: strdup allocates correct size
}

// ============================================================================
// 12. UNTRUSTED INPUT FOR A CONDITION (CWE-807)
// ============================================================================

struct User {
    int is_admin;
    char username[32];
};

// TRUE POSITIVE: Security decision based on user-controlled field
void tainted_condition_vulnerable(struct User *user) {
    // Bug: is_admin could be controlled by attacker in user-provided struct
    if (user->is_admin) {
        // Privileged operation
        system("rm -rf /tmp/cache");
    }
}

// TRUE POSITIVE: Auth decision based on network data
void tainted_condition_network(int sockfd) {
    int auth_result;
    recv(sockfd, &auth_result, sizeof(auth_result), 0);
    // Bug: auth_result comes directly from network
    if (auth_result == 1) {
        printf("Access granted\n");
        // Privileged operations...
    }
}

// FALSE POSITIVE: Condition based on local computation
void tainted_condition_safe_local(const char *password) {
    const char *correct = "secret123";
    // Safe: comparison is done locally
    int match = (strcmp(password, correct) == 0);
    if (match) {
        printf("Access granted\n");
    }
}

// FALSE POSITIVE: Verified through trusted function
int verify_admin_internal(int user_id);  // Trusted internal function

void tainted_condition_safe_verified(int user_id) {
    // Safe: admin status verified through trusted internal function
    if (verify_admin_internal(user_id)) {
        printf("Admin access granted\n");
    }
}

// ============================================================================
// 13. CALL TO MEMSET MAY BE DELETED (CWE-014)
// ============================================================================

// TRUE POSITIVE: Memset before free - may be optimized away
void memset_deleted_vulnerable(void) {
    char *password = malloc(64);
    if (password) {
        strcpy(password, "supersecret");
        // ... use password ...
        
        // Bug: Compiler may remove this since password is freed next
        memset(password, 0, 64);
        free(password);  // Password may still be in memory
    }
}

// TRUE POSITIVE: Local buffer cleared before return
void memset_deleted_stack(void) {
    char key[32];
    // ... use key for crypto ...
    
    // Bug: May be optimized away since key goes out of scope
    memset(key, 0, sizeof(key));
}  // Key data may remain on stack

// FALSE POSITIVE: Using volatile to prevent optimization
void memset_safe_volatile(void) {
    char *password = malloc(64);
    if (password) {
        strcpy(password, "supersecret");
        // ... use password ...
        
        // Safe: volatile prevents optimization
        volatile char *vp = (volatile char *)password;
        for (size_t i = 0; i < 64; i++) {
            vp[i] = 0;
        }
        free(password);
    }
}

// FALSE POSITIVE: Using explicit_bzero (not optimized away)
void memset_safe_explicit(void) {
    char *password = malloc(64);
    if (password) {
        strcpy(password, "supersecret");
        // ... use password ...
        
        // Safe: explicit_bzero is not optimized away
        explicit_bzero(password, 64);
        free(password);
    }
}

// ============================================================================
// 14. UNTERMINATED VARIADIC CALL (CWE-121)
// ============================================================================

// TRUE POSITIVE: execl without NULL terminator
void variadic_vulnerable_execl(void) {
    char *cmd = "/bin/echo";
    char *arg = "hello";
    // Bug: Missing NULL terminator
    execl(cmd, cmd, arg);  // Will read garbage from stack
}

// TRUE POSITIVE: execlp without proper termination
void variadic_vulnerable_execlp(char *script) {
    // Bug: Missing NULL
    execlp("sh", "sh", "-c", script);
}

// FALSE POSITIVE: Properly terminated with NULL
void variadic_safe_execl(void) {
    char *cmd = "/bin/echo";
    char *arg = "hello";
    execl(cmd, cmd, arg, NULL);  // Correct: NULL terminated
}

// FALSE POSITIVE: Using explicit (char*)NULL
void variadic_safe_explicit_null(char *script) {
    execlp("sh", "sh", "-c", script, (char *)NULL);  // Safe
}

// ============================================================================
// 15. UNSIGNED DIFFERENCE EXPRESSION COMPARED TO ZERO (CWE-191)
// ============================================================================

// TRUE POSITIVE: Unsigned subtraction compared to < 0
int unsigned_diff_vulnerable(unsigned int a, unsigned int b) {
    // Bug: a - b is unsigned, can never be < 0
    if (a - b < 0) {  // ALWAYS FALSE due to unsigned wrap
        return -1;
    }
    return a - b;
}

// TRUE POSITIVE: Loop condition with unsigned underflow
void unsigned_diff_loop(unsigned int start, unsigned int count) {
    unsigned int i;
    // Bug: when start < count, start - count wraps to large number
    for (i = 0; i < start - count; i++) {  // May loop many times
        printf("%u\n", i);
    }
}

// TRUE POSITIVE: Size calculation underflow
void unsigned_diff_size(unsigned int total, unsigned int used) {
    // Bug: if used > total, this underflows to huge value
    size_t remaining = total - used;
    if (remaining > 0) {  // Always true for unsigned!
        char *buf = malloc(remaining);  // Huge allocation or wrap
        free(buf);
    }
}

// FALSE POSITIVE: Proper check before subtraction
int unsigned_diff_safe_check(unsigned int a, unsigned int b) {
    // Safe: check before subtraction
    if (a < b) {
        return -1;
    }
    return a - b;  // Safe: a >= b guaranteed
}

// FALSE POSITIVE: Using signed types
int signed_diff_safe(int a, int b) {
    // Safe: signed subtraction can be negative
    if (a - b < 0) {
        return -1;
    }
    return a - b;
}

// FALSE POSITIVE: Cast to signed before comparison
int unsigned_diff_safe_cast(unsigned int a, unsigned int b) {
    // Safe: cast to signed for comparison
    if ((int)(a - b) < 0) {
        return -1;
    }
    return a - b;
}

// ============================================================================
// MAIN FUNCTION
// ============================================================================

int main(int argc, char *argv[]) {
    printf("Vulnerability test cases for 15 new CodeQL queries\n");
    printf("This file contains both TRUE POSITIVES and FALSE POSITIVES\n");
    
    // These would need actual implementation to test
    // Listed here to ensure functions are referenced
    
    if (argc > 1) {
        toctou_vulnerable(argv[1]);
        array_index_vulnerable();
        path_traversal_vulnerable();
    }
    
    return 0;
}
