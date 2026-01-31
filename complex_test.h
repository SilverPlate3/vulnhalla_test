// complex_test.h - Header for complex test case to exercise all Vulnhalla LLM tools
// This test case is designed to require the LLM to use:
//   1. get_caller_function - deep call chain requires climbing up
//   2. get_function_code - helper functions spread across files
//   3. get_class - struct definitions needed to understand data flow
//   4. get_global_var - global config affects vulnerability
//   5. get_macro - macros define buffer sizes and validation rules

#ifndef COMPLEX_TEST_H
#define COMPLEX_TEST_H

#include <stddef.h>
#include <stdint.h>

// ============================================================================
// MACROS - LLM must retrieve these to understand vulnerability
// ============================================================================

// Buffer size macros - crucial for understanding overflow potential
#define MAX_REQUEST_SIZE    1024
#define MAX_PAYLOAD_SIZE    512
#define HEADER_MAGIC        0xDEADBEEF
#define MIN_HEADER_SIZE     16

// Security validation macros
#define IS_VALID_MAGIC(x)   ((x) == HEADER_MAGIC)
#define PAYLOAD_OFFSET(hdr) ((hdr)->header_size)

// Boundary check macro - BUGGY! Off by one
#define BOUNDS_CHECK(idx, max)  ((idx) <= (max))  // BUG: should be <, not <=

// Safe bounds check for comparison
#define SAFE_BOUNDS_CHECK(idx, max)  ((idx) < (max))

// ============================================================================
// STRUCTURES - LLM must retrieve to understand data layout
// ============================================================================

// Request header structure - received from network
typedef struct RequestHeader {
    uint32_t magic;           // Should be HEADER_MAGIC
    uint32_t total_size;      // Total request size
    uint32_t header_size;     // Size of this header
    uint32_t payload_size;    // Size of payload data
    uint32_t flags;           // Request flags
    uint32_t checksum;        // Simple checksum
} RequestHeader;

// Request payload - contains actual data
typedef struct RequestPayload {
    uint8_t  type;            // Payload type
    uint8_t  priority;        // Priority level
    uint16_t reserved;        // Padding
    uint32_t data_length;     // Length of data array
    char     data[];          // Flexible array member
} RequestPayload;

// Full request structure
typedef struct Request {
    RequestHeader   header;
    RequestPayload *payload;
    char           *raw_data;    // Raw received data
    size_t          raw_size;    // Size of raw data
} Request;

// Processing context - holds state during request processing
typedef struct ProcessingContext {
    int      socket_fd;       // Source socket
    int      auth_level;      // Authentication level (0=none, 1=user, 2=admin)
    char    *username;        // Authenticated user
    char     output_buffer[MAX_REQUEST_SIZE];  // Buffer for response
    size_t   output_size;     // Current output size
} ProcessingContext;

// Configuration structure
typedef struct ServerConfig {
    int      debug_mode;      // Enable debug logging
    int      max_connections; // Max concurrent connections
    size_t   max_request_size;// Maximum request size allowed
    int      require_auth;    // Require authentication
    char    *log_file;        // Log file path
} ServerConfig;

// ============================================================================
// GLOBAL VARIABLE DECLARATIONS - LLM must retrieve to understand config
// ============================================================================

// Global configuration - affects security checks
extern ServerConfig g_server_config;

// Global statistics
extern volatile int g_requests_processed;
extern volatile int g_requests_failed;

// ============================================================================
// FUNCTION DECLARATIONS - Forms the call chain
// ============================================================================

// Entry point - called from main()
int handle_client_connection(int client_fd);

// Level 1 - processes the request
int process_user_request(ProcessingContext *ctx, const char *raw_data, size_t data_len);

// Level 2 - validates request structure
int validate_request_data(Request *req, ProcessingContext *ctx);

// Level 3 - validates payload bounds
int validate_payload_bounds(RequestPayload *payload, size_t max_size);

// Level 4 - THE VULNERABLE FUNCTION - copies data with bounds check
int copy_payload_data(char *dest, size_t dest_size, const RequestPayload *payload);

// Helper functions
int parse_request_header(RequestHeader *hdr, const char *data, size_t len);
int verify_checksum(const RequestHeader *hdr, const char *data);
RequestPayload *extract_payload(const Request *req);
void log_request(const Request *req, const char *status);
int check_authentication(ProcessingContext *ctx);
void update_statistics(int success);

// Utility functions
uint32_t compute_checksum(const void *data, size_t len);
int safe_copy(char *dest, size_t dest_size, const char *src, size_t src_len);

#endif // COMPLEX_TEST_H
