#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// ORIGINAL VULNERABILITIES (4)
// ============================================================================

// CWE-78: Command Injection
void command_injection(char *user_input) {
    char cmd[256];
    sprintf(cmd, "echo %s", user_input);
    system(cmd);
}

// CWE-120: Buffer Overflow via strcpy
void buffer_overflow(char *src) {
    char dest[10];
    strcpy(dest, src);  // No bounds check
}

// CWE-134: Format String
void format_string(char *user_input) {
    printf(user_input);  // User controls format string
}

// CWE-119: Copy using source size
void copy_source_size(char *src, size_t src_len) {
    char dest[10];
    memcpy(dest, src, src_len);  // Uses source size, not dest size
}

// ============================================================================
// NEW VULNERABILITIES - USE AFTER FREE (CWE-416)
// ============================================================================

// UAF #1: Simple use after free
void use_after_free_simple(void) {
    char *ptr = malloc(100);
    strcpy(ptr, "hello");
    free(ptr);
    printf("%s\n", ptr);  // UAF: accessing freed memory
}

// UAF #2: Use after free in conditional
void use_after_free_conditional(int flag) {
    char *data = malloc(50);
    if (flag) {
        free(data);
    }
    data[0] = 'x';  // UAF if flag was true
}

// ============================================================================
// NEW VULNERABILITIES - DOUBLE FREE (CWE-415)
// ============================================================================

// Double free #1: Simple double free
void double_free_simple(void) {
    char *ptr = malloc(100);
    free(ptr);
    free(ptr);  // Double free
}

// Double free #2: Conditional double free
void double_free_conditional(int error) {
    char *buffer = malloc(256);
    if (error) {
        free(buffer);
    }
    // ... more code ...
    free(buffer);  // Double free if error was true
}

// ============================================================================
// NEW VULNERABILITIES - NULL POINTER DEREFERENCE (CWE-476)
// ============================================================================

// NULL deref #1: Missing malloc check
void null_deref_malloc(size_t size) {
    char *ptr = malloc(size);
    // Missing: if (ptr == NULL) return;
    ptr[0] = 'A';  // Could be NULL
}

// NULL deref #2: Missing fopen check
void null_deref_fopen(const char *filename) {
    FILE *fp = fopen(filename, "r");
    // Missing NULL check
    fgetc(fp);  // Could be NULL
    fclose(fp);
}

// ============================================================================
// NEW VULNERABILITIES - INTEGER OVERFLOW (CWE-190)
// ============================================================================

// Integer overflow #1: In allocation size
void integer_overflow_alloc(unsigned int user_count) {
    size_t size = user_count * sizeof(int);  // Can overflow
    int *arr = malloc(size);
    // Small allocation, large write
    for (unsigned int i = 0; i < user_count; i++) {
        arr[i] = 0;
    }
    free(arr);
}

// Integer overflow #2: In arithmetic
int integer_overflow_arithmetic(int user_value) {
    int result = user_value * 1000;  // Can overflow
    return result;
}

// ============================================================================
// NEW VULNERABILITIES - BUFFER OVERFLOW VIA MEMORY FUNCTIONS (CWE-119/121/122)
// ============================================================================

// Buffer overflow #1: memcpy with wrong size
void buffer_overflow_memcpy(char *input, size_t input_len) {
    char buffer[64];
    memcpy(buffer, input, input_len);  // No check against buffer size
}

// Buffer overflow #2: memset overflow
void buffer_overflow_memset(size_t len) {
    char buffer[32];
    memset(buffer, 0, len);  // len could exceed 32
}

// ============================================================================
// NEW VULNERABILITIES - STATIC ARRAY OVERFLOW (CWE-119/131)
// ============================================================================

// Static overflow #1: Array index out of bounds
void static_overflow_index(int index) {
    int arr[10];
    arr[index] = 42;  // index could be >= 10
}

// Static overflow #2: Loop bounds error
void static_overflow_loop(int count) {
    char buffer[100];
    for (int i = 0; i <= count; i++) {  // Off-by-one if count == 100
        buffer[i] = 'A';
    }
}

// ============================================================================
// NEW VULNERABILITIES - UNCONTROLLED ALLOCATION SIZE (CWE-789)
// ============================================================================

// Uncontrolled alloc #1: Direct user size
void uncontrolled_alloc_direct(size_t user_size) {
    char *buffer = malloc(user_size);  // Attacker controls size
    if (buffer) {
        memset(buffer, 0, user_size);
        free(buffer);
    }
}

// Uncontrolled alloc #2: Calculated from user input
void uncontrolled_alloc_calculated(int width, int height) {
    size_t size = width * height * 4;  // RGB + alpha, attacker controls
    char *image = malloc(size);
    free(image);
}

// ============================================================================
// NEW VULNERABILITIES - INVALID POINTER DEREFERENCE / OFF-BY-ONE (CWE-193)
// ============================================================================

// Off-by-one #1: Loop with <= instead of <
void off_by_one_loop(int size) {
    int *arr = malloc(size * sizeof(int));
    for (int i = 0; i <= size; i++) {  // Should be i < size
        arr[i] = 0;
    }
    free(arr);
}

// Off-by-one #2: Pointer arithmetic
void off_by_one_pointer(char *data, size_t len) {
    char *end = data + len;
    for (char *p = data; p <= end; p++) {  // Should be p < end
        *p = 0;
    }
}

// ============================================================================
// NEW VULNERABILITIES - UNINITIALIZED VARIABLE (CWE-457)
// ============================================================================

// Uninitialized #1: Conditional initialization
int uninitialized_conditional(int flag) {
    int value;  // Not initialized
    if (flag) {
        value = 42;
    }
    return value;  // May be uninitialized
}

// Uninitialized #2: Struct with partial init
struct UserData {
    int id;
    char name[32];
    int permissions;
};

void uninitialized_struct(void) {
    struct UserData user;
    user.id = 1;
    // name and permissions not initialized
    printf("Permissions: %d\n", user.permissions);  // Uninitialized read
}

// ============================================================================
// NEW VULNERABILITIES - OVERRUNNING WRITE (CWE-120/787)
// ============================================================================

// Overrun #1: sprintf without bounds
void overrun_sprintf(char *username) {
    char greeting[32];
    sprintf(greeting, "Welcome, %s! Your session has started.", username);
}

// Overrun #2: strcat overflow
void overrun_strcat(char *suffix) {
    char buffer[16] = "prefix_";
    strcat(buffer, suffix);  // Could overflow
}

// Overrun #3: gets (classic)
void overrun_gets(void) {
    char buffer[64];
    gets(buffer);  // No bounds checking at all
}

// ============================================================================
// ADDITIONAL MEMORY CORRUPTION PATTERNS
// ============================================================================

// Heap overflow via realloc misuse
void heap_overflow_realloc(char *data, size_t old_size, size_t new_size) {
    char *ptr = malloc(old_size);
    memcpy(ptr, data, old_size);
    ptr = realloc(ptr, new_size);
    // If new_size < old_size, data beyond new_size is now out of bounds
    // But code might still access old_size bytes
    memset(ptr, 0, old_size);  // Could overflow if new_size < old_size
    free(ptr);
}

// Stack buffer overflow via recursive call
void stack_overflow_recursive(int depth, char *data) {
    char local_buffer[256];
    strcpy(local_buffer, data);  // Overflow
    if (depth > 0) {
        stack_overflow_recursive(depth - 1, local_buffer);
    }
}

// Type confusion / wrong sizeof
void wrong_sizeof(int count) {
    int *arr = malloc(count * sizeof(char));  // Wrong! Should be sizeof(int)
    for (int i = 0; i < count; i++) {
        arr[i] = i;  // Writing beyond allocation
    }
    free(arr);
}

// ============================================================================
// MAIN FUNCTION
// ============================================================================

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }

    // Original vulnerabilities
    command_injection(argv[1]);
    buffer_overflow(argv[1]);
    format_string(argv[1]);
    copy_source_size(argv[1], strlen(argv[1]));

    // New vulnerabilities
    use_after_free_simple();
    double_free_simple();
    null_deref_malloc(100);
    integer_overflow_alloc(atoi(argv[1]));
    buffer_overflow_memcpy(argv[1], strlen(argv[1]));
    static_overflow_index(atoi(argv[1]));
    uncontrolled_alloc_direct(atoi(argv[1]));
    off_by_one_loop(10);
    printf("Result: %d\n", uninitialized_conditional(argc > 2));
    overrun_sprintf(argv[1]);

    return 0;
}
