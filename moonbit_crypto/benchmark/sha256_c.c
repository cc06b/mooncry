#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// SHA-256 C 实现（优化版本）
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ ((~x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

static const unsigned int K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void sha256_block(unsigned int* state, const unsigned char* block) {
    unsigned int a = state[0], b = state[1], c = state[2], d = state[3];
    unsigned int e = state[4], f = state[5], g = state[6], h = state[7];
    unsigned int w[64];
    unsigned int t1, t2;
    
    // 消息扩展
    for (int i = 0; i < 16; i++) {
        w[i] = (block[i*4] << 24) | (block[i*4+1] << 16) | 
               (block[i*4+2] << 8) | block[i*4+3];
    }
    
    for (int i = 16; i < 64; i++) {
        w[i] = ROTR(w[i-2], 17) ^ ROTR(w[i-2], 19) ^ (w[i-2] >> 10) + 
               w[i-7] + ROTR(w[i-15], 7) ^ ROTR(w[i-15], 18) ^ (w[i-15] >> 3) + w[i-16];
    }
    
    // 主循环
    for (int i = 0; i < 64; i++) {
        t1 = h + ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25) + (e & f) ^ (~e & g) + K[i] + w[i];
        t2 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22) + (a & b) ^ (a & c) ^ (b & c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void sha256(const unsigned char* data, size_t len, unsigned char* output) {
    unsigned int state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    // 填充
    size_t block_count = (len + 8) / 64 + 1;
    if ((len + 9) % 64 < 1) block_count++;
    size_t total_len = block_count * 64;
    
    unsigned char* padded = (unsigned char*)calloc(total_len, 1);
    memcpy(padded, data, len);
    padded[len] = 0x80;
    
    unsigned long long bit_len = (unsigned long long)len * 8;
    padded[total_len - 8] = (bit_len >> 56) & 0xFF;
    padded[total_len - 7] = (bit_len >> 48) & 0xFF;
    padded[total_len - 6] = (bit_len >> 40) & 0xFF;
    padded[total_len - 5] = (bit_len >> 32) & 0xFF;
    padded[total_len - 4] = (bit_len >> 24) & 0xFF;
    padded[total_len - 3] = (bit_len >> 16) & 0xFF;
    padded[total_len - 2] = (bit_len >> 8) & 0xFF;
    padded[total_len - 1] = bit_len & 0xFF;
    
    // 处理所有块
    for (size_t i = 0; i < block_count; i++) {
        sha256_block(state, padded + i * 64);
    }
    
    // 输出
    for (int i = 0; i < 8; i++) {
        output[i*4] = (state[i] >> 24) & 0xFF;
        output[i*4+1] = (state[i] >> 16) & 0xFF;
        output[i*4+2] = (state[i] >> 8) & 0xFF;
        output[i*4+3] = state[i] & 0xFF;
    }
    
    free(padded);
}

double get_time_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

int main() {
    printf("======================================================================\n");
    printf("              SHA-256 性能对比测试 (C vs MoonBit)\n");
    printf("======================================================================\n\n");
    
    // 测试配置
    int iterations = 1000;
    int sizes[] = {64, 256, 1024, 4096, 16384, 65536, 262144};  // 字节
    int num_sizes = sizeof(sizes) / sizeof(sizes[0]);
    
    printf("C SHA-256 性能测试\n");
    printf("测试迭代次数: %d\n\n", iterations);
    
    printf("%-10s %12s %12s %12s\n", "数据大小", "总时间(ms)", "平均时间(μs)", "吞吐量(MB/s)");
    printf("%-10s %12s %12s %12s\n", "--------", "-----------", "-----------", "-----------");
    
    for (int s = 0; s < num_sizes; s++) {
        int size = sizes[s];
        unsigned char* data = (unsigned char*)malloc(size);
        for (int i = 0; i < size; i++) data[i] = i % 256;
        
        unsigned char hash[32];
        double start = get_time_ms();
        
        for (int iter = 0; iter < iterations; iter++) {
            sha256(data, size, hash);
        }
        
        double end = get_time_ms();
        double total_ms = end - start;
        double avg_us = (total_ms * 1000.0) / iterations;
        double throughput = (size * iterations) / (total_ms / 1000.0) / (1024.0 * 1024.0);
        
        printf("%-10d %12.2f %12.2f %12.2f\n", size, total_ms, avg_us, throughput);
        
        free(data);
    }
    
    printf("\n======================================================================\n");
    printf("测试完成！\n");
    printf("======================================================================\n");
    
    return 0;
}
