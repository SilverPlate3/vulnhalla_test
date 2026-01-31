// complex_test.c - Complex test case to exercise ALL Vulnhalla LLM tools
//
// This file contains a vulnerability that requires the LLM to:
//   1. get_caller_function - understand the 4-level deep call chain
//   2. get_function_code   - examine helper functions
//   3. get_class           - understand RequestHeader, RequestPayload, etc.
//   4. get_global_var      - check g_server_config for debug_mode
//   5. get_macro           - examine BOUNDS_CHECK macro (buggy)
//
// The vulnerability: Buffer overflow in copy_payload_data() due to:
//   - BOUNDS_CHECK macro uses <= instead of < (off-by-one)
//   - In debug mode, extra data is copied that can overflow
//
// Call chain: main -> handle_client_connection -> process_user_request 
//             -> validate_request_data -> validate_payload_bounds 
//             -> copy_payload_data (VULNERABLE)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "complex_test.h"

// ============================================================================
// GLOBAL VARIABLES - LLM must use get_global_var to understand these
// ============================================================================

// Server configuration - affects vulnerability exploitability
ServerConfig g_server_config = {
    .debug_mode = 1,           // Debug mode enables extra copying
    .max_connections = 100,
    .max_request_size = MAX_REQUEST_SIZE,
    .require_auth = 0,         // Auth disabled makes exploit easier
    .log_file = "/var/log/server.log"
};

// Statistics counters
volatile int g_requests_processed = 0;
volatile int g_requests_failed = 0;

// ============================================================================
// HELPER FUNCTIONS - LLM must use get_function_code to examine these
// ============================================================================

// Compute simple checksum
uint32_t compute_checksum(const void *data, size_t len) {
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += bytes[i];
        sum = (sum << 1) | (sum >> 31);  // Rotate left
    }
    return sum;
}

// Verify request checksum
int verify_checksum(const RequestHeader *hdr, const char *data) {
    if (!hdr || !data) return 0;
    uint32_t computed = compute_checksum(data + sizeof(RequestHeader), 
                                          hdr->payload_size);
    return (computed == hdr->checksum);
}

// Parse request header from raw data
int parse_request_header(RequestHeader *hdr, const char *data, size_t len) {
    if (len < sizeof(RequestHeader)) {
        return -1;  // Not enough data
    }
    memcpy(hdr, data, sizeof(RequestHeader));
    
    // Validate magic - uses IS_VALID_MAGIC macro
    if (!IS_VALID_MAGIC(hdr->magic)) {
        return -2;  // Invalid magic
    }
    
    // Check sizes are reasonable
    if (hdr->total_size > MAX_REQUEST_SIZE) {
        return -3;  // Request too large
    }
    if (hdr->header_size < MIN_HEADER_SIZE) {
        return -4;  // Header too small
    }
    
    return 0;
}

// Extract payload from request
RequestPayload *extract_payload(const Request *req) {
    if (!req || !req->raw_data) return NULL;
    
    // Payload starts after header
    size_t offset = PAYLOAD_OFFSET(&req->header);
    if (offset >= req->raw_size) return NULL;
    
    return (RequestPayload *)(req->raw_data + offset);
}

// Log request details
void log_request(const Request *req, const char *status) {
    if (!g_server_config.debug_mode) return;
    
    printf("[REQUEST] magic=%08x size=%u payload=%u status=%s\n",
           req->header.magic,
           req->header.total_size,
           req->header.payload_size,
           status);
}

// Check authentication
int check_authentication(ProcessingContext *ctx) {
    if (!g_server_config.require_auth) {
        ctx->auth_level = 2;  // Grant admin if auth disabled
        return 1;
    }
    // Would normally check credentials here
    return (ctx->auth_level > 0);
}

// Update global statistics
void update_statistics(int success) {
    if (success) {
        g_requests_processed++;
    } else {
        g_requests_failed++;
    }
}

// Safe copy function (for comparison with buggy version)
int safe_copy(char *dest, size_t dest_size, const char *src, size_t src_len) {
    if (!dest || !src) return -1;
    if (src_len >= dest_size) return -1;  // Correct: strict less than
    
    memcpy(dest, src, src_len);
    dest[src_len] = '\0';
    return 0;
}

// ============================================================================
// LEVEL 4 (DEEPEST): THE VULNERABLE FUNCTION
// LLM must climb call chain to understand context
// ============================================================================

// VULNERABLE: Buffer overflow due to off-by-one in BOUNDS_CHECK macro
// The macro uses <= instead of <, allowing one extra byte to be written
int copy_payload_data(char *dest, size_t dest_size, const RequestPayload *payload) {
    if (!dest || !payload) {
        return -1;
    }
    
    size_t copy_len = payload->data_length;
    
    // BUG: BOUNDS_CHECK uses <= instead of <
    // This allows copy_len == dest_size, causing off-by-one write
    // when we add null terminator below
    if (!BOUNDS_CHECK(copy_len, dest_size)) {
        return -2;  // Would reject, but off-by-one lets one extra through
    }
    
    // Copy the data
    memcpy(dest, payload->data, copy_len);
    
    // BUG: If copy_len == dest_size, this writes past buffer!
    // In debug mode, we also copy an extra debug byte
    if (g_server_config.debug_mode && copy_len > 0) {
        // Extra debug marker - EXPLOITS THE OFF-BY-ONE
        dest[copy_len] = payload->type;  // OVERFLOW when copy_len == dest_size
    }
    
    // Null terminate (another potential overflow)
    if (copy_len < dest_size) {
        dest[copy_len] = '\0';
    }
    
    return 0;
}

// ============================================================================
// LEVEL 3: Validates payload bounds before copying
// ============================================================================

int validate_payload_bounds(RequestPayload *payload, size_t max_size) {
    if (!payload) {
        return -1;
    }
    
    // Check payload type is valid
    if (payload->type > 10) {
        return -2;  // Unknown type
    }
    
    // Check data length against maximum - but uses same buggy macro!
    if (!BOUNDS_CHECK(payload->data_length, max_size)) {
        return -3;
    }
    
    return 0;
}

// ============================================================================
// LEVEL 2: Validates the full request structure
// ============================================================================

int validate_request_data(Request *req, ProcessingContext *ctx) {
    if (!req || !ctx) {
        return -1;
    }
    
    // Verify checksum if required
    if (req->header.flags & 0x01) {
        if (!verify_checksum(&req->header, req->raw_data)) {
            log_request(req, "CHECKSUM_FAIL");
            return -2;
        }
    }
    
    // Extract and validate payload
    RequestPayload *payload = extract_payload(req);
    if (!payload) {
        log_request(req, "NO_PAYLOAD");
        return -3;
    }
    
    // Validate payload bounds
    int ret = validate_payload_bounds(payload, MAX_PAYLOAD_SIZE);
    if (ret != 0) {
        log_request(req, "BOUNDS_FAIL");
        return -4;
    }
    
    // Copy payload data to output buffer - THIS TRIGGERS THE VULNERABILITY
    ret = copy_payload_data(ctx->output_buffer, sizeof(ctx->output_buffer), payload);
    if (ret != 0) {
        log_request(req, "COPY_FAIL");
        return -5;
    }
    
    ctx->output_size = payload->data_length;
    log_request(req, "OK");
    return 0;
}

// ============================================================================
// LEVEL 1: Main request processing entry point
// ============================================================================

int process_user_request(ProcessingContext *ctx, const char *raw_data, size_t data_len) {
    if (!ctx || !raw_data) {
        return -1;
    }
    
    // Check authentication
    if (!check_authentication(ctx)) {
        return -2;  // Not authenticated
    }
    
    // Build request structure
    Request req = {0};
    req.raw_data = (char *)raw_data;  // Cast away const for internal use
    req.raw_size = data_len;
    
    // Parse header
    int ret = parse_request_header(&req.header, raw_data, data_len);
    if (ret != 0) {
        update_statistics(0);
        return -3;
    }
    
    // Validate and process
    ret = validate_request_data(&req, ctx);
    if (ret != 0) {
        update_statistics(0);
        return -4;
    }
    
    update_statistics(1);
    return 0;
}

// ============================================================================
// ENTRY POINT: Handle client connection
// ============================================================================

int handle_client_connection(int client_fd) {
    char buffer[MAX_REQUEST_SIZE];
    
    // Read request from client
    ssize_t bytes_read = recv(client_fd, buffer, sizeof(buffer), 0);
    if (bytes_read <= 0) {
        return -1;
    }
    
    // Set up processing context
    ProcessingContext ctx = {0};
    ctx.socket_fd = client_fd;
    ctx.auth_level = 0;
    ctx.username = NULL;
    ctx.output_size = 0;
    
    // Process the request
    int result = process_user_request(&ctx, buffer, bytes_read);
    
    // Send response if successful
    if (result == 0 && ctx.output_size > 0) {
        send(client_fd, ctx.output_buffer, ctx.output_size, 0);
    }
    
    return result;
}

// ============================================================================
// MAIN FUNCTION
// ============================================================================

int main(int argc, char *argv[]) {
    printf("Complex Test Case - Exercises all Vulnhalla LLM tools\n");
    printf("=====================================================\n\n");
    
    printf("This test has a vulnerability in copy_payload_data() that requires:\n");
    printf("  1. get_caller_function - climb 4-level call chain\n");
    printf("  2. get_function_code   - examine helper functions\n");
    printf("  3. get_class           - understand struct definitions\n");
    printf("  4. get_global_var      - check g_server_config\n");
    printf("  5. get_macro           - examine BOUNDS_CHECK macro\n\n");
    
    if (argc > 1) {
        // Simulate with file input for testing
        int fd = open(argv[1], 0);  // O_RDONLY
        if (fd >= 0) {
            handle_client_connection(fd);
            close(fd);
        }
    } else {
        // Create a test request that triggers the vulnerability
        printf("Creating exploit payload...\n");
        
        // Build a request that exploits the off-by-one
        char exploit_data[MAX_REQUEST_SIZE];
        memset(exploit_data, 0, sizeof(exploit_data));
        
        RequestHeader *hdr = (RequestHeader *)exploit_data;
        hdr->magic = HEADER_MAGIC;
        hdr->total_size = sizeof(RequestHeader) + sizeof(RequestPayload) + MAX_PAYLOAD_SIZE;
        hdr->header_size = sizeof(RequestHeader);
        hdr->payload_size = sizeof(RequestPayload) + MAX_PAYLOAD_SIZE;
        hdr->flags = 0;
        
        RequestPayload *payload = (RequestPayload *)(exploit_data + sizeof(RequestHeader));
        payload->type = 1;
        payload->priority = 0;
        payload->data_length = MAX_REQUEST_SIZE;  // Triggers off-by-one!
        
        // Fill data
        memset(payload->data, 'A', MAX_PAYLOAD_SIZE);
        
        // Process it
        ProcessingContext ctx = {0};
        ctx.auth_level = 2;
        
        printf("Processing exploit request with data_length=%u (buffer size=%d)\n",
               payload->data_length, MAX_REQUEST_SIZE);
        
        int result = process_user_request(&ctx, exploit_data, sizeof(exploit_data));
        printf("Result: %d\n", result);
        printf("Requests processed: %d, failed: %d\n", 
               g_requests_processed, g_requests_failed);
    }
    
    return 0;
}
