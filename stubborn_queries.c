// stubborn_queries.c - Patterns for the 6 hardest queries

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

// ============================================================================
// 1. MUTEX LOCKED TWICE
// The query uses LockFlow.qll for interprocedural analysis
// ============================================================================

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

// Helper that locks
void do_lock(void) {
    pthread_mutex_lock(&mtx);
}

// Function that calls lock when mutex might already be held
void maybe_double_lock(int already_locked) {
    if (!already_locked) {
        pthread_mutex_lock(&mtx);
    }
    // Do work
    do_lock();  // Second lock via helper - might be double
    pthread_mutex_unlock(&mtx);
    pthread_mutex_unlock(&mtx);
}

// Direct pattern
void direct_double_lock(void) {
    pthread_mutex_lock(&mtx);
    pthread_mutex_lock(&mtx);  // Direct double lock
    pthread_mutex_unlock(&mtx);
    pthread_mutex_unlock(&mtx);
}

// ============================================================================
// 2. UNTERMINATED VARIADIC CALL
// Needs 80% of calls to a function to have terminator
// ============================================================================

void variadic_test(void) {
    // 5 good calls with NULL
    execl("/bin/true", "true", (char*)NULL);
    execl("/bin/true", "true", (char*)NULL);
    execl("/bin/true", "true", (char*)NULL);
    execl("/bin/true", "true", (char*)NULL);
    execl("/bin/true", "true", (char*)NULL);
    // 1 bad call without NULL (16.6% bad = 83.4% good)
    execl("/bin/echo", "echo", "missing");
}

// Same with execlp
void variadic_test2(void) {
    execlp("true", "true", (char*)NULL);
    execlp("true", "true", (char*)NULL);
    execlp("true", "true", (char*)NULL);
    execlp("true", "true", (char*)NULL);
    execlp("true", "true", (char*)NULL);
    execlp("echo", "echo", "bad");  // Missing NULL
}

// ============================================================================
// 3. UNSIGNED DIFFERENCE COMPARED TO ZERO
// Need: (unsigned subtraction) < 0 in RelationalOperation
// ============================================================================

int unsigned_diff_1(unsigned a, unsigned b) {
    // Direct pattern
    if (a - b < 0) {  // Always false
        return -1;
    }
    return 0;
}

int unsigned_diff_2(void) {
    unsigned x = 10, y = 20;
    unsigned diff = x - y;
    // Comparison with zero
    if (diff < 0) {  // Always false for unsigned
        return 1;
    }
    return 0;
}

// ============================================================================
// 4. CALL TO MEMSET MAY BE DELETED
// Need: memset on local var with no subsequent use
// ============================================================================

void memset_stack_no_use(void) {
    char password[64];
    strcpy(password, "secret");
    // Use it
    printf("password=%s\n", password);
    // Memset then return - may be deleted
    memset(password, 0, sizeof(password));
}

char *memset_heap_return(void) {
    char *data = malloc(64);
    if (data) {
        strcpy(data, "sensitive");
        char *copy = strdup(data);
        memset(data, 0, 64);  // May be deleted - data not used after
        free(data);
        return copy;
    }
    return NULL;
}

// ============================================================================
// 5. CONDITIONALLY UNINITIALIZED VARIABLE
// Need: initialization function like scanf whose return isn't checked
// ============================================================================

int cond_uninit_scanf(void) {
    int value;
    scanf("%d", &value);  // Return not checked
    return value;  // May be uninitialized
}

int cond_uninit_sscanf(const char *str) {
    int num;
    sscanf(str, "%d", &num);  // Return not checked
    return num;
}

int cond_uninit_fscanf(FILE *fp) {
    int val;
    fscanf(fp, "%d", &val);  // Return not checked
    return val;
}

// ============================================================================
// 6. UNTRUSTED INPUT FOR A CONDITION  
// Need: FlowSource -> condition -> raisesPrivilege
// ============================================================================

void untrusted_setuid(void) {
    char buf[32];
    if (fgets(buf, sizeof(buf), stdin)) {
        if (atoi(buf) == 1) {
            setuid(0);  // Privilege based on stdin
        }
    }
}

void untrusted_setgid(void) {
    char *val = getenv("ADMIN");
    if (val && atoi(val) > 0) {
        setgid(0);  // Privilege based on env
    }
}

void untrusted_seteuid(void) {
    char input[16];
    ssize_t n = read(STDIN_FILENO, input, sizeof(input)-1);
    if (n > 0) {
        input[n] = '\0';
        if (atoi(input)) {
            seteuid(0);  // Privilege based on read
        }
    }
}

// ============================================================================
// MAIN
// ============================================================================

int main(void) {
    printf("Stubborn query tests\n");
    
    // Call functions to compile them
    direct_double_lock();
    variadic_test();
    variadic_test2();
    unsigned_diff_1(5, 10);
    unsigned_diff_2();
    memset_stack_no_use();
    free(memset_heap_return());
    cond_uninit_scanf();
    untrusted_setuid();
    
    return 0;
}
