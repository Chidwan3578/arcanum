/**
 * CUDA BLAKE3 Implementation
 *
 * Optimized for NVIDIA RTX 4500 (Ada Lovelace) and similar GPUs.
 * Designed for batch hashing of many independent messages.
 *
 * Performance target: 50+ GiB/s for batch operations
 *
 * Build with: nvcc -O3 -arch=sm_89 blake3_cuda.cu -o blake3_cuda
 */

#include <cuda_runtime.h>
#include <stdint.h>
#include <stdio.h>

// BLAKE3 Constants
__constant__ uint32_t IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

// Message schedule permutations for each round
__constant__ uint8_t MSG_SCHEDULE[7][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
    {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
    {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
    {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
    {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
    {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13}
};

// Flag constants
#define CHUNK_START 1
#define CHUNK_END   2
#define PARENT      4
#define ROOT        8
#define CHUNK_LEN   1024
#define BLOCK_LEN   64

// Rotate right
__device__ __forceinline__ uint32_t rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

// G function - quarter round
__device__ __forceinline__ void g(
    uint32_t* state,
    int a, int b, int c, int d,
    uint32_t mx, uint32_t my
) {
    state[a] = state[a] + state[b] + mx;
    state[d] = rotr(state[d] ^ state[a], 16);
    state[c] = state[c] + state[d];
    state[b] = rotr(state[b] ^ state[c], 12);
    state[a] = state[a] + state[b] + my;
    state[d] = rotr(state[d] ^ state[a], 8);
    state[c] = state[c] + state[d];
    state[b] = rotr(state[b] ^ state[c], 7);
}

// One round of compression
__device__ __forceinline__ void round_fn(uint32_t* state, const uint32_t* m, int round) {
    // Column step
    g(state, 0, 4, 8, 12, m[MSG_SCHEDULE[round][0]], m[MSG_SCHEDULE[round][1]]);
    g(state, 1, 5, 9, 13, m[MSG_SCHEDULE[round][2]], m[MSG_SCHEDULE[round][3]]);
    g(state, 2, 6, 10, 14, m[MSG_SCHEDULE[round][4]], m[MSG_SCHEDULE[round][5]]);
    g(state, 3, 7, 11, 15, m[MSG_SCHEDULE[round][6]], m[MSG_SCHEDULE[round][7]]);

    // Diagonal step
    g(state, 0, 5, 10, 15, m[MSG_SCHEDULE[round][8]], m[MSG_SCHEDULE[round][9]]);
    g(state, 1, 6, 11, 12, m[MSG_SCHEDULE[round][10]], m[MSG_SCHEDULE[round][11]]);
    g(state, 2, 7, 8, 13, m[MSG_SCHEDULE[round][12]], m[MSG_SCHEDULE[round][13]]);
    g(state, 3, 4, 9, 14, m[MSG_SCHEDULE[round][14]], m[MSG_SCHEDULE[round][15]]);
}

// Compress one block
__device__ void compress(
    const uint32_t cv[8],
    const uint8_t* block,
    uint64_t counter,
    uint32_t block_len,
    uint8_t flags,
    uint32_t out[16]
) {
    // Initialize state
    uint32_t state[16];
    for (int i = 0; i < 8; i++) {
        state[i] = cv[i];
        state[i + 8] = IV[i];
    }
    state[12] = (uint32_t)counter;
    state[13] = (uint32_t)(counter >> 32);
    state[14] = block_len;
    state[15] = (uint32_t)flags;

    // Load message words (little-endian)
    uint32_t m[16];
    for (int i = 0; i < 16; i++) {
        const uint8_t* p = block + i * 4;
        m[i] = p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
    }

    // 7 rounds
    round_fn(state, m, 0);
    round_fn(state, m, 1);
    round_fn(state, m, 2);
    round_fn(state, m, 3);
    round_fn(state, m, 4);
    round_fn(state, m, 5);
    round_fn(state, m, 6);

    // Output
    for (int i = 0; i < 8; i++) {
        out[i] = state[i] ^ state[i + 8];
    }
    for (int i = 8; i < 16; i++) {
        out[i] = state[i] ^ cv[i - 8];
    }
}

// Hash a single chunk (up to 1024 bytes)
__device__ void hash_chunk(
    const uint8_t* data,
    uint32_t len,
    const uint32_t key[8],
    uint64_t chunk_counter,
    uint8_t flags,
    uint32_t cv_out[8]
) {
    uint32_t cv[8];
    for (int i = 0; i < 8; i++) cv[i] = key[i];

    uint32_t blocks = (len + BLOCK_LEN - 1) / BLOCK_LEN;
    if (blocks == 0) blocks = 1;

    for (uint32_t b = 0; b < blocks; b++) {
        uint8_t block_data[BLOCK_LEN] = {0};
        uint32_t block_len = min(BLOCK_LEN, len - b * BLOCK_LEN);

        // Copy block data
        for (uint32_t i = 0; i < block_len; i++) {
            block_data[i] = data[b * BLOCK_LEN + i];
        }

        uint8_t block_flags = flags;
        if (b == 0) block_flags |= CHUNK_START;
        if (b == blocks - 1) block_flags |= CHUNK_END;

        uint32_t out[16];
        compress(cv, block_data, chunk_counter, block_len, block_flags, out);

        for (int i = 0; i < 8; i++) cv[i] = out[i];
    }

    for (int i = 0; i < 8; i++) cv_out[i] = cv[i];
}

// Kernel: Hash multiple independent messages
// Each block handles one message
__global__ void blake3_hash_batch_kernel(
    const uint8_t* __restrict__ messages,  // All messages concatenated
    const uint32_t* __restrict__ lengths,  // Length of each message
    const uint64_t* __restrict__ offsets,  // Offset of each message in buffer
    uint8_t* __restrict__ hashes,          // Output: 32 bytes per message
    uint32_t num_messages
) {
    uint32_t msg_idx = blockIdx.x;
    if (msg_idx >= num_messages) return;

    // Get message info
    const uint8_t* msg = messages + offsets[msg_idx];
    uint32_t len = lengths[msg_idx];
    uint8_t* hash_out = hashes + msg_idx * 32;

    // For single-chunk messages (≤ 1024 bytes), use simple path
    if (len <= CHUNK_LEN) {
        uint32_t cv[8];
        hash_chunk(msg, len, IV, 0, ROOT, cv);

        // Write output
        for (int i = 0; i < 8; i++) {
            hash_out[i * 4 + 0] = cv[i] & 0xFF;
            hash_out[i * 4 + 1] = (cv[i] >> 8) & 0xFF;
            hash_out[i * 4 + 2] = (cv[i] >> 16) & 0xFF;
            hash_out[i * 4 + 3] = (cv[i] >> 24) & 0xFF;
        }
        return;
    }

    // Multi-chunk path
    uint32_t num_chunks = (len + CHUNK_LEN - 1) / CHUNK_LEN;

    // Allocate CVs on stack (max reasonable: ~64 chunks = 64KB message)
    // For larger messages, would need different approach
    uint32_t cvs[64][8];

    // Hash all chunks
    for (uint32_t c = 0; c < num_chunks && c < 64; c++) {
        uint32_t chunk_offset = c * CHUNK_LEN;
        uint32_t chunk_len = min(CHUNK_LEN, len - chunk_offset);
        hash_chunk(msg + chunk_offset, chunk_len, IV, c, 0, cvs[c]);
    }

    // Merge CVs to root (simplified binary tree)
    uint32_t level_size = num_chunks;
    while (level_size > 1) {
        uint32_t next_level_size = (level_size + 1) / 2;
        for (uint32_t i = 0; i < level_size / 2; i++) {
            // Combine cvs[i*2] and cvs[i*2+1]
            uint8_t parent_block[BLOCK_LEN] = {0};
            for (int j = 0; j < 8; j++) {
                parent_block[j * 4 + 0] = cvs[i * 2][j] & 0xFF;
                parent_block[j * 4 + 1] = (cvs[i * 2][j] >> 8) & 0xFF;
                parent_block[j * 4 + 2] = (cvs[i * 2][j] >> 16) & 0xFF;
                parent_block[j * 4 + 3] = (cvs[i * 2][j] >> 24) & 0xFF;
                parent_block[32 + j * 4 + 0] = cvs[i * 2 + 1][j] & 0xFF;
                parent_block[32 + j * 4 + 1] = (cvs[i * 2 + 1][j] >> 8) & 0xFF;
                parent_block[32 + j * 4 + 2] = (cvs[i * 2 + 1][j] >> 16) & 0xFF;
                parent_block[32 + j * 4 + 3] = (cvs[i * 2 + 1][j] >> 24) & 0xFF;
            }

            uint8_t flags = PARENT;
            if (next_level_size == 1 && i == 0 && level_size == 2) {
                flags |= ROOT;
            }

            uint32_t out[16];
            compress(IV, parent_block, 0, BLOCK_LEN, flags, out);
            for (int j = 0; j < 8; j++) cvs[i][j] = out[j];
        }

        // If odd number, copy last one
        if (level_size % 2 == 1) {
            for (int j = 0; j < 8; j++) {
                cvs[next_level_size - 1][j] = cvs[level_size - 1][j];
            }
        }
        level_size = next_level_size;
    }

    // Write final hash
    for (int i = 0; i < 8; i++) {
        hash_out[i * 4 + 0] = cvs[0][i] & 0xFF;
        hash_out[i * 4 + 1] = (cvs[0][i] >> 8) & 0xFF;
        hash_out[i * 4 + 2] = (cvs[0][i] >> 16) & 0xFF;
        hash_out[i * 4 + 3] = (cvs[0][i] >> 24) & 0xFF;
    }
}

// Optimized kernel for small messages (≤ 1KB each)
// Uses warp-level parallelism for compression
__global__ void blake3_hash_small_batch_kernel(
    const uint8_t* __restrict__ messages,  // Messages concatenated
    uint32_t message_size,                  // Fixed size per message
    uint8_t* __restrict__ hashes,          // Output: 32 bytes per message
    uint32_t num_messages
) {
    // Each warp (32 threads) processes one message
    uint32_t warp_idx = (blockIdx.x * blockDim.x + threadIdx.x) / 32;
    uint32_t lane = threadIdx.x % 32;

    if (warp_idx >= num_messages) return;

    const uint8_t* msg = messages + warp_idx * message_size;
    uint8_t* hash_out = hashes + warp_idx * 32;

    // Collaborative loading of message into shared memory
    __shared__ uint8_t smem[32 * 1024];  // 1KB per warp, max 32 warps per block
    uint8_t* warp_smem = smem + (threadIdx.x / 32) * 1024;

    // Each lane loads 32 bytes (covers 1KB with 32 threads)
    if (lane * 32 < message_size) {
        for (int i = 0; i < 32 && lane * 32 + i < message_size; i++) {
            warp_smem[lane * 32 + i] = msg[lane * 32 + i];
        }
    }
    __syncwarp();

    // Single-chunk hash (thread 0 does the work, could be parallelized further)
    if (lane == 0) {
        uint32_t cv[8];
        hash_chunk(warp_smem, message_size, IV, 0, ROOT, cv);

        for (int i = 0; i < 8; i++) {
            hash_out[i * 4 + 0] = cv[i] & 0xFF;
            hash_out[i * 4 + 1] = (cv[i] >> 8) & 0xFF;
            hash_out[i * 4 + 2] = (cv[i] >> 16) & 0xFF;
            hash_out[i * 4 + 3] = (cv[i] >> 24) & 0xFF;
        }
    }
}

// Host API

extern "C" {

typedef struct {
    uint8_t* d_messages;
    uint32_t* d_lengths;
    uint64_t* d_offsets;
    uint8_t* d_hashes;
    size_t buffer_size;
} Blake3CudaContext;

// Initialize CUDA context
int blake3_cuda_init(Blake3CudaContext* ctx, size_t max_buffer_size, uint32_t max_messages) {
    cudaError_t err;

    err = cudaMalloc(&ctx->d_messages, max_buffer_size);
    if (err != cudaSuccess) return -1;

    err = cudaMalloc(&ctx->d_lengths, max_messages * sizeof(uint32_t));
    if (err != cudaSuccess) { cudaFree(ctx->d_messages); return -2; }

    err = cudaMalloc(&ctx->d_offsets, max_messages * sizeof(uint64_t));
    if (err != cudaSuccess) {
        cudaFree(ctx->d_messages);
        cudaFree(ctx->d_lengths);
        return -3;
    }

    err = cudaMalloc(&ctx->d_hashes, max_messages * 32);
    if (err != cudaSuccess) {
        cudaFree(ctx->d_messages);
        cudaFree(ctx->d_lengths);
        cudaFree(ctx->d_offsets);
        return -4;
    }

    ctx->buffer_size = max_buffer_size;
    return 0;
}

// Hash a batch of messages
int blake3_cuda_hash_batch(
    Blake3CudaContext* ctx,
    const uint8_t* messages,
    const uint32_t* lengths,
    const uint64_t* offsets,
    uint32_t num_messages,
    size_t total_size,
    uint8_t* hashes_out
) {
    cudaError_t err;

    // Copy input to device
    err = cudaMemcpy(ctx->d_messages, messages, total_size, cudaMemcpyHostToDevice);
    if (err != cudaSuccess) return -1;

    err = cudaMemcpy(ctx->d_lengths, lengths, num_messages * sizeof(uint32_t), cudaMemcpyHostToDevice);
    if (err != cudaSuccess) return -2;

    err = cudaMemcpy(ctx->d_offsets, offsets, num_messages * sizeof(uint64_t), cudaMemcpyHostToDevice);
    if (err != cudaSuccess) return -3;

    // Launch kernel - one block per message
    blake3_hash_batch_kernel<<<num_messages, 1>>>(
        ctx->d_messages,
        ctx->d_lengths,
        ctx->d_offsets,
        ctx->d_hashes,
        num_messages
    );

    err = cudaDeviceSynchronize();
    if (err != cudaSuccess) return -4;

    // Copy results back
    err = cudaMemcpy(hashes_out, ctx->d_hashes, num_messages * 32, cudaMemcpyDeviceToHost);
    if (err != cudaSuccess) return -5;

    return 0;
}

// Hash batch of fixed-size small messages (optimized path)
int blake3_cuda_hash_small_batch(
    Blake3CudaContext* ctx,
    const uint8_t* messages,
    uint32_t message_size,    // Must be ≤ 1024
    uint32_t num_messages,
    uint8_t* hashes_out
) {
    if (message_size > 1024) return -1;

    cudaError_t err;
    size_t total_size = (size_t)message_size * num_messages;

    // Copy input to device
    err = cudaMemcpy(ctx->d_messages, messages, total_size, cudaMemcpyHostToDevice);
    if (err != cudaSuccess) return -2;

    // Launch optimized kernel - 32 threads per message (1 warp)
    int threads_per_block = 256;  // 8 warps
    int warps_per_block = threads_per_block / 32;
    int blocks = (num_messages + warps_per_block - 1) / warps_per_block;

    blake3_hash_small_batch_kernel<<<blocks, threads_per_block>>>(
        ctx->d_messages,
        message_size,
        ctx->d_hashes,
        num_messages
    );

    err = cudaDeviceSynchronize();
    if (err != cudaSuccess) return -3;

    // Copy results back
    err = cudaMemcpy(hashes_out, ctx->d_hashes, num_messages * 32, cudaMemcpyDeviceToHost);
    if (err != cudaSuccess) return -4;

    return 0;
}

// Cleanup
void blake3_cuda_cleanup(Blake3CudaContext* ctx) {
    cudaFree(ctx->d_messages);
    cudaFree(ctx->d_lengths);
    cudaFree(ctx->d_offsets);
    cudaFree(ctx->d_hashes);
}

// Get device info
void blake3_cuda_device_info() {
    int device;
    cudaGetDevice(&device);

    cudaDeviceProp prop;
    cudaGetDeviceProperties(&prop, device);

    printf("CUDA Device: %s\n", prop.name);
    printf("  Compute capability: %d.%d\n", prop.major, prop.minor);
    printf("  SM count: %d\n", prop.multiProcessorCount);
    printf("  Max threads/block: %d\n", prop.maxThreadsPerBlock);
    printf("  Shared mem/block: %zu KB\n", prop.sharedMemPerBlock / 1024);
    printf("  Global memory: %.1f GB\n", prop.totalGlobalMem / (1024.0 * 1024.0 * 1024.0));
}

}  // extern "C"

// Test/benchmark main
#ifdef BUILD_TEST

#include <chrono>
#include <vector>
#include <random>

int main() {
    blake3_cuda_device_info();

    // Test batch hashing
    const int NUM_MESSAGES = 10000;
    const int MESSAGE_SIZE = 1024;  // 1KB each

    std::vector<uint8_t> messages(NUM_MESSAGES * MESSAGE_SIZE);
    std::vector<uint8_t> hashes(NUM_MESSAGES * 32);

    // Fill with random data
    std::mt19937 rng(42);
    for (auto& b : messages) b = rng() & 0xFF;

    Blake3CudaContext ctx;
    int err = blake3_cuda_init(&ctx, NUM_MESSAGES * MESSAGE_SIZE, NUM_MESSAGES);
    if (err != 0) {
        printf("Init failed: %d\n", err);
        return 1;
    }

    // Warmup
    blake3_cuda_hash_small_batch(&ctx, messages.data(), MESSAGE_SIZE, NUM_MESSAGES, hashes.data());

    // Benchmark
    auto start = std::chrono::high_resolution_clock::now();

    const int ITERATIONS = 100;
    for (int i = 0; i < ITERATIONS; i++) {
        blake3_cuda_hash_small_batch(&ctx, messages.data(), MESSAGE_SIZE, NUM_MESSAGES, hashes.data());
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    double total_bytes = (double)NUM_MESSAGES * MESSAGE_SIZE * ITERATIONS;
    double throughput_gbps = (total_bytes / (1024.0 * 1024.0 * 1024.0)) / (duration / 1e6);

    printf("\nBenchmark: %d messages x %d bytes x %d iterations\n",
           NUM_MESSAGES, MESSAGE_SIZE, ITERATIONS);
    printf("Time: %.2f ms\n", duration / 1000.0);
    printf("Throughput: %.2f GiB/s\n", throughput_gbps);

    // Print first hash
    printf("\nFirst hash: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", hashes[i]);
    }
    printf("\n");

    blake3_cuda_cleanup(&ctx);
    return 0;
}

#endif  // BUILD_TEST
