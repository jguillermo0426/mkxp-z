/*
** voidpak.cpp
**
** Pokémon Void Encrypted Archive (VOIDPAK v1) for mkxp-z
** Implements PhysFS archiver with ChaCha20 stream decryption and zlib support.
*/

#include "voidpak.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <zlib.h>

#include <string>
#include <vector>
#include <map>
#include <algorithm>

// --- Obfuscated Master Encryption Key ---
// Generated for Pokemon Void. XOR masked with 0x5A to prevent plain text extraction.
static const uint8_t KEY_MASK = 0x5A;
static const uint8_t OBFUSCATED_KEY[32] = {
    0xc3, 0xe7, 0xde, 0x83, 0x0c, 0x42, 0x5f, 0x91,
    0x21, 0x89, 0x8d, 0x75, 0x1d, 0x95, 0xcf, 0xa2,
    0x18, 0xc6, 0xe8, 0x81, 0x0a, 0xf8, 0xae, 0xa9,
    0x48, 0x93, 0x3b, 0xf8, 0x79, 0x54, 0x73, 0x1c
};

static void getMasterKey(uint8_t outKey[32]) {
    for (int i = 0; i < 32; ++i) {
        outKey[i] = OBFUSCATED_KEY[i] ^ KEY_MASK;
    }
}

// ============================================================================
// Internal SHA-256 & HMAC-SHA256 Implementation (Self-Contained)
// ============================================================================

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
} Sha256Ctx;

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22))
#define EP1(x) (ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25))
#define SIG0(x) (ROR32(x, 7) ^ ROR32(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROR32(x, 17) ^ ROR32(x, 19) ^ ((x) >> 10))

static const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha256_transform(Sha256Ctx *ctx, const uint8_t data[64]) {
    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
    uint32_t w[64];

    for (int i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)data[i * 4] << 24) |
               ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) |
               ((uint32_t)data[i * 4 + 3]);
    }
    for (int i = 16; i < 64; ++i) {
        w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];
    }
    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = h + EP1(e) + CH(e, f, g) + SHA256_K[i] + w[i];
        uint32_t t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(Sha256Ctx *ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

static void sha256_update(Sha256Ctx *ctx, const uint8_t *data, size_t len) {
    size_t buf_idx = (size_t)(ctx->count % 64);
    ctx->count += len;
    while (len > 0) {
        size_t to_copy = 64 - buf_idx;
        if (to_copy > len) to_copy = len;
        memcpy(ctx->buffer + buf_idx, data, to_copy);
        buf_idx = (buf_idx + to_copy) % 64;
        data += to_copy;
        len -= to_copy;
        if (buf_idx == 0) {
            sha256_transform(ctx, ctx->buffer);
        }
    }
}

static void sha256_final(Sha256Ctx *ctx, uint8_t hash[32]) {
    uint8_t pad = 0x80;
    uint64_t bit_len = ctx->count * 8;
    sha256_update(ctx, &pad, 1);
    uint8_t zero = 0;
    while ((ctx->count % 64) != 56) {
        sha256_update(ctx, &zero, 1);
    }
    uint8_t len_bytes[8];
    for (int i = 0; i < 8; ++i) {
        len_bytes[i] = (uint8_t)(bit_len >> (56 - i * 8));
    }
    sha256_update(ctx, len_bytes, 8);
    for (int i = 0; i < 8; ++i) {
        hash[i * 4]     = (uint8_t)(ctx->state[i] >> 24);
        hash[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        hash[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        hash[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

static void hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t out_mac[32]) {
    uint8_t k[64];
    memset(k, 0, 64);
    if (key_len > 64) {
        Sha256Ctx kctx;
        sha256_init(&kctx);
        sha256_update(&kctx, key, key_len);
        sha256_final(&kctx, k);
    } else {
        memcpy(k, key, key_len);
    }

    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    Sha256Ctx ictx;
    sha256_init(&ictx);
    sha256_update(&ictx, ipad, 64);
    sha256_update(&ictx, data, data_len);
    uint8_t inner_hash[32];
    sha256_final(&ictx, inner_hash);

    Sha256Ctx octx;
    sha256_init(&octx);
    sha256_update(&octx, opad, 64);
    sha256_update(&octx, inner_hash, 32);
    sha256_final(&octx, out_mac);
}

// ============================================================================
// ChaCha20 Stream Cipher Implementation (Matching Python Cryptography 16-Byte Nonce)
// ============================================================================

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
#define QR(a, b, c, d) \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d,  8); \
    c += d; b ^= c; b = ROTL32(b,  7);

static inline uint32_t load32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void store32_le(uint8_t *p, uint32_t val) {
    p[0] = (uint8_t)(val);
    p[1] = (uint8_t)(val >> 8);
    p[2] = (uint8_t)(val >> 16);
    p[3] = (uint8_t)(val >> 24);
}

static void chacha20_block(const uint32_t state[16], uint8_t stream[64]) {
    uint32_t x[16];
    for (int i = 0; i < 16; ++i) x[i] = state[i];

    for (int i = 0; i < 10; ++i) {
        QR(x[0], x[4], x[ 8], x[12]);
        QR(x[1], x[5], x[ 9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[ 8], x[13]);
        QR(x[3], x[4], x[ 9], x[14]);
    }

    for (int i = 0; i < 16; ++i) {
        store32_le(stream + i * 4, x[i] + state[i]);
    }
}

// Decrypts data starting at an arbitrary byte offset into the stream
static void chacha20_crypt_stream(const uint8_t key[32], const uint8_t nonce[16],
                                  uint64_t byte_offset, uint8_t *data, size_t len) {
    if (len == 0) return;

    uint32_t state[16];
    // Constants "expand 32-byte k"
    state[0] = 0x61707865; state[1] = 0x3320646e;
    state[2] = 0x79622d32; state[3] = 0x6b206574;

    for (int i = 0; i < 8; ++i) {
        state[4 + i] = load32_le(key + i * 4);
    }

    // Python cryptography library ChaCha20 layout:
    // 64-bit initial counter in state[12..13] initialized to nonce[0..7]
    // 64-bit nonce in state[14..15] initialized to nonce[8..15]
    uint64_t base_counter = (uint64_t)load32_le(nonce + 0) | ((uint64_t)load32_le(nonce + 4) << 32);
    uint64_t block_counter = byte_offset / 64;
    size_t block_offset = (size_t)(byte_offset % 64);

    state[14] = load32_le(nonce + 8);
    state[15] = load32_le(nonce + 12);

    uint8_t stream[64];
    size_t processed = 0;

    while (processed < len) {
        uint64_t cur_counter = base_counter + block_counter;
        state[12] = (uint32_t)(cur_counter & 0xFFFFFFFF);
        state[13] = (uint32_t)((cur_counter >> 32) & 0xFFFFFFFF);
        chacha20_block(state, stream);
        block_counter++;

        size_t available = 64 - block_offset;
        size_t chunk = (len - processed < available) ? (len - processed) : available;

        for (size_t i = 0; i < chunk; ++i) {
            data[processed + i] ^= stream[block_offset + i];
        }

        processed += chunk;
        block_offset = 0; // After first block, offset is always 0
    }
}

// ============================================================================
// VOIDPAK Data Structures
// ============================================================================

struct VoidEntry {
    std::string path;
    uint64_t offset;
    uint64_t size;
    uint64_t origSize;
    uint32_t crc;
    uint8_t compressed;
    uint64_t fileIndex;
};

struct VoidArchive {
    PHYSFS_Io *archiveIo;
    uint8_t dataKey[32];
    std::map<std::string, VoidEntry> entryMap;
    std::map<std::string, std::vector<std::string>> dirMap;

    ~VoidArchive() {
        if (archiveIo) {
            archiveIo->destroy(archiveIo);
        }
    }
};

struct VoidFileHandle {
    VoidEntry entry;
    uint64_t currentOffset;
    PHYSFS_Io *io;
    uint8_t fileNonce[16];
    uint8_t *cachedData; // Decompressed buffer for compressed files
    uint8_t dataKey[32];

    VoidFileHandle() : currentOffset(0), io(NULL), cachedData(NULL) {}

    ~VoidFileHandle() {
        if (cachedData) {
            free(cachedData);
            cachedData = NULL;
        }
        if (io) {
            io->destroy(io);
            io = NULL;
        }
    }
};

// ============================================================================
// PhysFS I/O Operations for VoidFileHandle
// ============================================================================

static PHYSFS_sint64 VOID_ioRead(PHYSFS_Io *io, void *buf, PHYSFS_uint64 len) {
    VoidFileHandle *handle = (VoidFileHandle *)io->opaque;
    if (!handle) return -1;

    uint64_t totalSize = handle->entry.origSize;
    if (handle->currentOffset >= totalSize) return 0; // EOF

    uint64_t toRead = (len > totalSize - handle->currentOffset) ? (totalSize - handle->currentOffset) : len;

    if (handle->cachedData) {
        // Fast in-memory copy for decompressed entries
        memcpy(buf, handle->cachedData + handle->currentOffset, toRead);
        handle->currentOffset += toRead;
        return (PHYSFS_sint64)toRead;
    }

    // Streaming read directly from archive for uncompressed entries (Audio / Graphics)
    PHYSFS_Io *archIo = handle->io;
    uint64_t rawFileOffset = handle->entry.offset + handle->currentOffset;
    if (!archIo->seek(archIo, rawFileOffset)) {
        return -1;
    }

    PHYSFS_sint64 bytesRead = archIo->read(archIo, buf, toRead);
    if (bytesRead <= 0) return bytesRead;

    // Decrypt chunk on the fly
    chacha20_crypt_stream(handle->dataKey, handle->fileNonce,
                          handle->currentOffset, (uint8_t *)buf, (size_t)bytesRead);

    handle->currentOffset += bytesRead;
    return bytesRead;
}

static int VOID_ioSeek(PHYSFS_Io *io, PHYSFS_uint64 offset) {
    VoidFileHandle *handle = (VoidFileHandle *)io->opaque;
    if (!handle) return 0;
    if (offset > handle->entry.origSize) return 0;

    handle->currentOffset = offset;
    return 1;
}

static PHYSFS_sint64 VOID_ioTell(PHYSFS_Io *io) {
    VoidFileHandle *handle = (VoidFileHandle *)io->opaque;
    return handle ? (PHYSFS_sint64)handle->currentOffset : -1;
}

static PHYSFS_sint64 VOID_ioLength(PHYSFS_Io *io) {
    VoidFileHandle *handle = (VoidFileHandle *)io->opaque;
    return handle ? (PHYSFS_sint64)handle->entry.origSize : -1;
}

static PHYSFS_Io *VOID_ioDuplicate(PHYSFS_Io *io);

static void VOID_ioDestroy(PHYSFS_Io *io) {
    if (io) {
        VoidFileHandle *handle = (VoidFileHandle *)io->opaque;
        if (handle) delete handle;
        PHYSFS_getAllocator()->Free(io);
    }
}

static const PHYSFS_Io VOID_IoTemplate = {
    0, // version
    NULL, // opaque
    VOID_ioRead,
    NULL, // write
    VOID_ioSeek,
    VOID_ioTell,
    VOID_ioLength,
    VOID_ioDuplicate,
    NULL, // flush
    VOID_ioDestroy
};

static PHYSFS_Io *VOID_ioDuplicate(PHYSFS_Io *io) {
    VoidFileHandle *orig = (VoidFileHandle *)io->opaque;
    if (!orig) return NULL;

    VoidFileHandle *clone = new VoidFileHandle();
    clone->entry = orig->entry;
    clone->currentOffset = orig->currentOffset;
    clone->io = orig->io ? orig->io->duplicate(orig->io) : NULL;
    memcpy(clone->fileNonce, orig->fileNonce, 16);
    memcpy(clone->dataKey, orig->dataKey, 32);

    if (orig->cachedData) {
        clone->cachedData = (uint8_t *)malloc(orig->entry.origSize);
        if (clone->cachedData) {
            memcpy(clone->cachedData, orig->cachedData, orig->entry.origSize);
        }
    }

    PHYSFS_Io *dupIo = (PHYSFS_Io *)PHYSFS_getAllocator()->Malloc(sizeof(PHYSFS_Io));
    *dupIo = VOID_IoTemplate;
    dupIo->opaque = clone;
    return dupIo;
}

// ============================================================================
// Helper Utilities for Archive Reading
// ============================================================================

static inline uint16_t readU16LE(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static inline uint32_t readU32LE(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline uint64_t readU64LE(const uint8_t *p) {
    return (uint64_t)readU32LE(p) | ((uint64_t)readU32LE(p + 4) << 32);
}

// Populate directory hierarchies for every ancestor of `path`.
// For example, "Audio/BGM/test.ogg" adds:
//   dirMap[""]       <- "Audio"
//   dirMap["Audio"]  <- "BGM"
//   dirMap["Audio/BGM"] <- "test.ogg"
static void indexDirectories(VoidArchive *archive, const std::string &path) {
    // Walk each path component and ensure each parent directory
    // knows about its child (be it a sub-directory or a file).
    size_t start = 0;
    while (start <= path.size()) {
        size_t slash = path.find('/', start);
        // Component is path[start..slash-1] (or end if no slash)
        std::string parentDir = (start == 0) ? "" : path.substr(0, start - 1);
        std::string childName;

        if (slash == std::string::npos) {
            // Final component — the filename itself
            childName = path.substr(start);
            if (childName.empty()) break;
            auto &dirList = archive->dirMap[parentDir];
            if (std::find(dirList.begin(), dirList.end(), childName) == dirList.end())
                dirList.push_back(childName);
            break;
        } else {
            // Intermediate component — a directory name
            childName = path.substr(start, slash - start);
            if (!childName.empty()) {
                auto &dirList = archive->dirMap[parentDir];
                if (std::find(dirList.begin(), dirList.end(), childName) == dirList.end())
                    dirList.push_back(childName);
            }
            start = slash + 1;
        }
    }
}

// ============================================================================
// PhysFS Archiver Implementation
// ============================================================================

static void *VOID_openArchive(PHYSFS_Io *io, const char *name, int forWrite, int *claimed) {
    (void)name;
    if (forWrite) return NULL;

    // Check Header Magic: "VOIDPAK1"
    uint8_t magic[8];
    if (io->read(io, magic, 8) != 8 || memcmp(magic, "VOIDPAK1", 8) != 0) {
        return NULL;
    }
    *claimed = 1;

    uint8_t salt[16];
    if (io->read(io, salt, 16) != 16) return NULL;

    uint8_t headerNums[24];
    if (io->read(io, headerNums, 24) != 24) return NULL;

    uint64_t fileCount   = readU64LE(headerNums);
    (void)fileCount;
    uint64_t tableOffset = readU64LE(headerNums + 8);
    uint64_t tableLen    = readU64LE(headerNums + 16);

    uint8_t storedAuthTag[32];
    if (io->read(io, storedAuthTag, 32) != 32) return NULL;

    // Derive cryptographic subkeys
    uint8_t masterKey[32];
    getMasterKey(masterKey);

    uint8_t tableKey[32], dataKey[32], authKey[32];
    // tableKey = HMAC(masterKey, salt + "VOID_TABLE_KEY")
    uint8_t kdfBuf[64];
    memcpy(kdfBuf, salt, 16);

    memcpy(kdfBuf + 16, "VOID_TABLE_KEY", 14);
    hmac_sha256(masterKey, 32, kdfBuf, 30, tableKey);

    memcpy(kdfBuf + 16, "VOID_DATA_KEY", 13);
    hmac_sha256(masterKey, 32, kdfBuf, 29, dataKey);

    memcpy(kdfBuf + 16, "VOID_AUTH_KEY", 13);
    hmac_sha256(masterKey, 32, kdfBuf, 29, authKey);

    // Verify Header Authentication Tag
    uint8_t authPayload[40];
    memcpy(authPayload, salt, 16);
    memcpy(authPayload + 16, headerNums, 24);

    uint8_t expectedTag[32];
    hmac_sha256(authKey, 32, authPayload, 40, expectedTag);

    if (memcmp(storedAuthTag, expectedTag, 32) != 0) {
        // Key mismatch or archive corrupted
        return NULL;
    }

    // Read and decrypt File Directory Table
    if (!io->seek(io, tableOffset)) return NULL;

    uint8_t *encTable = (uint8_t *)malloc(tableLen);
    if (!encTable) return NULL;

    if ((uint64_t)io->read(io, encTable, tableLen) != tableLen) {
        free(encTable);
        return NULL;
    }

    uint8_t tableNonce[32];
    hmac_sha256(tableKey, 32, (const uint8_t *)"TABLE_NONCE", 11, tableNonce);

    chacha20_crypt_stream(tableKey, tableNonce, 0, encTable, (size_t)tableLen);

    // Decompress zlib directory table
    uLongf destLen = (uLongf)(tableLen * 10 + 65536);
    uint8_t *decompTable = (uint8_t *)malloc(destLen);
    if (!decompTable) {
        free(encTable);
        return NULL;
    }

    int zret = uncompress(decompTable, &destLen, encTable, (uLong)tableLen);
    while (zret == Z_BUF_ERROR) {
        destLen *= 2;
        uint8_t *newBuf = (uint8_t *)realloc(decompTable, destLen);
        if (!newBuf) {
            free(encTable);
            free(decompTable);
            return NULL;
        }
        decompTable = newBuf;
        zret = uncompress(decompTable, &destLen, encTable, (uLong)tableLen);
    }
    free(encTable);

    if (zret != Z_OK) {
        free(decompTable);
        return NULL;
    }

    // Parse Directory Table
    VoidArchive *archive = new VoidArchive();
    archive->archiveIo = io->duplicate(io);
    memcpy(archive->dataKey, dataKey, 32);

    const uint8_t *ptr = decompTable;
    const uint8_t *end = decompTable + destLen;

    while (ptr < end) {
        if (ptr + 2 > end) break;
        uint16_t pathLen = readU16LE(ptr); ptr += 2;
        if (ptr + pathLen > end) break;

        std::string relPath((const char *)ptr, pathLen); ptr += pathLen;
        if (ptr + 37 > end) break;

        uint64_t offset   = readU64LE(ptr); ptr += 8;
        uint64_t size     = readU64LE(ptr); ptr += 8;
        uint64_t origSize = readU64LE(ptr); ptr += 8;
        uint32_t crc      = readU32LE(ptr); ptr += 4;
        uint8_t comp      = *ptr++;
        uint64_t fIdx     = readU64LE(ptr); ptr += 8;

        VoidEntry entry;
        entry.path = relPath;
        entry.offset = offset;
        entry.size = size;
        entry.origSize = origSize;
        entry.crc = crc;
        entry.compressed = comp;
        entry.fileIndex = fIdx;

        archive->entryMap[relPath] = entry;
        indexDirectories(archive, relPath);
    }

    free(decompTable);
    return archive;
}

static PHYSFS_EnumerateCallbackResult VOID_enumerate(void *opaque, const char *dirname,
                                                     PHYSFS_EnumerateCallback cb,
                                                     const char *origdir, void *callbackdata) {
    VoidArchive *archive = (VoidArchive *)opaque;
    if (!archive) return PHYSFS_ENUM_ERROR;

    std::string d(dirname);
    for (char &c : d) if (c == '\\') c = '/';
    // Strip leading and trailing slashes
    while (!d.empty() && d.front() == '/') d.erase(d.begin());
    while (!d.empty() && d.back() == '/') d.pop_back();

    auto it = archive->dirMap.find(d);
    if (it == archive->dirMap.end()) {
        return PHYSFS_ENUM_OK;
    }

    for (const std::string &item : it->second) {
        PHYSFS_EnumerateCallbackResult res = cb(callbackdata, origdir, item.c_str());
        if (res != PHYSFS_ENUM_OK) return res;
    }

    return PHYSFS_ENUM_OK;
}

static PHYSFS_Io *VOID_openRead(void *opaque, const char *fnm) {
    VoidArchive *archive = (VoidArchive *)opaque;
    if (!archive) return NULL;

    std::string path(fnm);
    for (char &c : path) if (c == '\\') c = '/';
    while (!path.empty() && path.front() == '/') path.erase(path.begin());

    auto it = archive->entryMap.find(path);
    if (it == archive->entryMap.end()) {
        PHYSFS_setErrorCode(PHYSFS_ERR_NOT_FOUND);
        return NULL;
    }

    const VoidEntry &entry = it->second;
    VoidFileHandle *handle = new VoidFileHandle();
    handle->entry = entry;
    handle->currentOffset = 0;
    handle->io = archive->archiveIo->duplicate(archive->archiveIo);
    memcpy(handle->dataKey, archive->dataKey, 32);

    // Derive file-specific 16-byte nonce: HMAC(dataKey, "FILE_NONCE:" + index)
    uint8_t nonceInput[20];
    memcpy(nonceInput, "FILE_NONCE:", 11);
    uint64_t idxLE = entry.fileIndex;
    memcpy(nonceInput + 11, &idxLE, 8);
    uint8_t fullNonce[32];
    hmac_sha256(archive->dataKey, 32, nonceInput, 19, fullNonce);
    memcpy(handle->fileNonce, fullNonce, 16);

    if (entry.compressed == 1) {
        // Pre-decompress small files into memory
        uint8_t *encBuf = (uint8_t *)malloc(entry.size);
        if (!encBuf || !handle->io->seek(handle->io, entry.offset) ||
            (uint64_t)handle->io->read(handle->io, encBuf, entry.size) != entry.size) {
            if (encBuf) free(encBuf);
            delete handle;
            return NULL;
        }

        chacha20_crypt_stream(handle->dataKey, handle->fileNonce, 0, encBuf, (size_t)entry.size);

        handle->cachedData = (uint8_t *)malloc(entry.origSize);
        uLongf destLen = (uLongf)entry.origSize;
        if (!handle->cachedData || uncompress(handle->cachedData, &destLen, encBuf, (uLong)entry.size) != Z_OK) {
            free(encBuf);
            delete handle;
            return NULL;
        }
        free(encBuf);
    }

    PHYSFS_Io *retIo = (PHYSFS_Io *)PHYSFS_getAllocator()->Malloc(sizeof(PHYSFS_Io));
    *retIo = VOID_IoTemplate;
    retIo->opaque = handle;
    return retIo;
}

static PHYSFS_Io *VOID_openWrite(void *opaque, const char *filename) {
    (void)opaque; (void)filename;
    PHYSFS_setErrorCode(PHYSFS_ERR_READ_ONLY);
    return NULL;
}

static PHYSFS_Io *VOID_openAppend(void *opaque, const char *filename) {
    (void)opaque; (void)filename;
    PHYSFS_setErrorCode(PHYSFS_ERR_READ_ONLY);
    return NULL;
}

static int VOID_remove(void *opaque, const char *filename) {
    (void)opaque; (void)filename;
    PHYSFS_setErrorCode(PHYSFS_ERR_READ_ONLY);
    return 0;
}

static int VOID_mkdir(void *opaque, const char *filename) {
    (void)opaque; (void)filename;
    PHYSFS_setErrorCode(PHYSFS_ERR_READ_ONLY);
    return 0;
}

static int VOID_stat(void *opaque, const char *fn, PHYSFS_Stat *stat) {
    VoidArchive *archive = (VoidArchive *)opaque;
    if (!archive) return 0;

    std::string path(fn);
    for (char &c : path) if (c == '\\') c = '/';
    while (!path.empty() && path.front() == '/') path.erase(path.begin());

    bool isFile = (archive->entryMap.find(path) != archive->entryMap.end());
    bool isDir  = (archive->dirMap.find(path) != archive->dirMap.end()) || path.empty();

    if (!isFile && !isDir) {
        PHYSFS_setErrorCode(PHYSFS_ERR_NOT_FOUND);
        return 0;
    }

    stat->modtime = 0;
    stat->createtime = 0;
    stat->accesstime = 0;
    stat->readonly = 1;

    if (isFile) {
        stat->filesize = archive->entryMap[path].origSize;
        stat->filetype = PHYSFS_FILETYPE_REGULAR;
    } else {
        stat->filesize = 0;
        stat->filetype = PHYSFS_FILETYPE_DIRECTORY;
    }

    return 1;
}

static void VOID_closeArchive(void *opaque) {
    VoidArchive *archive = (VoidArchive *)opaque;
    if (archive) {
        delete archive;
    }
}

// PhysFS Archiver Definition
const PHYSFS_Archiver VOIDPAK_Archiver = {
    0, // version
    {
        "VOIDPAK",
        "Pokemon Void Encrypted Container",
        "Void Team",
        "",
        0 // no symlinks
    },
    VOID_openArchive,
    VOID_enumerate,
    VOID_openRead,
    VOID_openWrite,
    VOID_openAppend,
    VOID_remove,
    VOID_mkdir,
    VOID_stat,
    VOID_closeArchive
};
