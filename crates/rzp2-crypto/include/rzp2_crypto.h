#ifndef RZP2_CRYPTO_H
#define RZP2_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * RZP2 加密 / 解密动态库（ML-KEM + ChaCha20-Poly1305 + Argon2id）。
 *
 * kem_id 取值：
 *   0 = ML-KEM-512          1 = ML-KEM-768          2 = ML-KEM-1024
 *   3 = ML-KEM-512-X25519   4 = ML-KEM-768-X25519   5 = ML-KEM-1024-X25519
 *
 * 返回码约定：
 *   >= 0  成功（加解密为写出字节数；查询容量时为所需字节数；keygen/derive 为 0）
 *   -1    参数错误 / 格式错误
 *   -2    输出缓冲区不足
 *   -3    认证失败（密钥错误或数据被篡改）
 */

/* 指定 KEM 参数集的公钥 / 私钥字节数；kem_id 非法返回 -1。 */
intptr_t rzp2_kem_public_key_size(uint32_t kem_id);
intptr_t rzp2_kem_secret_key_size(uint32_t kem_id);

/* 生成密钥对，成功返回 0。pk_out / sk_out 需按上面的 size 预分配。 */
intptr_t rzp2_kem_keygen(uint32_t kem_id, uint8_t *pk_out, uint8_t *sk_out);

/*
 * 混合加密（ML-KEM 或 ML-KEM+X25519 封装 + ChaCha20-Poly1305）。
 * 密文布局：kem_ct_len(4, LE) | kem_ct | nonce(12) | tag(16) | ct。
 * out 传 NULL 返回所需缓冲区字节数。
 */
intptr_t rzp2_crypto_encrypt(uint32_t kem_id,
                             const uint8_t *recipient_pk, size_t pk_len,
                             const uint8_t *plaintext, size_t pt_len,
                             uint8_t *out, size_t out_cap);

/* 混合解密。out 传 NULL 返回所需缓冲区字节数；认证失败返回 -3。 */
intptr_t rzp2_crypto_decrypt(uint32_t kem_id,
                             const uint8_t *recipient_sk, size_t sk_len,
                             const uint8_t *ciphertext, size_t ct_len,
                             uint8_t *out, size_t out_cap);

/*
 * ChaCha20-Poly1305 AEAD。key 32 字节，nonce 12 字节。
 * 密文布局：ct | tag(16)。out 传 NULL 返回所需缓冲区字节数。
 */
intptr_t rzp2_aead_encrypt(const uint8_t *key, const uint8_t *nonce,
                           const uint8_t *plaintext, size_t pt_len,
                           const uint8_t *aad, size_t aad_len,
                           uint8_t *out, size_t out_cap);
intptr_t rzp2_aead_decrypt(const uint8_t *key, const uint8_t *nonce,
                           const uint8_t *ciphertext, size_t ct_len,
                           const uint8_t *aad, size_t aad_len,
                           uint8_t *out, size_t out_cap);

/* Argon2id 口令派生 32 字节密钥，成功返回 0。 */
intptr_t rzp2_derive_key(const uint8_t *password, size_t pw_len,
                         const uint8_t *salt, size_t salt_len,
                         uint32_t memory_kib, uint32_t iterations, uint32_t lanes,
                         uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif /* RZP2_CRYPTO_H */
