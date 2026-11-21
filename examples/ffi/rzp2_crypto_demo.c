/*
 * RZP2 加密/解密动态库使用示例（C）。
 *
 * 编译（Linux，链接 .so）：
 *   gcc -o crypto_demo examples/ffi/rzp2_crypto_demo.c \
 *       -Icrates/rzp2-crypto/include -Ltarget/release -lrzp2_crypto \
 *       -Wl,-rpath,target/release
 *
 * Windows（MinGW，链接 .dll）：
 *   gcc -o crypto_demo.exe examples/ffi/rzp2_crypto_demo.c \
 *       -Icrates/rzp2-crypto/include -Ltarget/release -lrzp2_crypto
 *   （运行前把 rzp2_crypto.dll 放到 exe 同目录或 PATH 中）
 */
#include "rzp2_crypto.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    const uint32_t kem_id = 1; /* ML-KEM-768 */
    const char *msg = "这是一条需要加密的敏感消息。";
    const size_t msg_len = strlen(msg);

    /* 1) 生成密钥对。 */
    const intptr_t pk_len = rzp2_kem_public_key_size(kem_id);
    const intptr_t sk_len = rzp2_kem_secret_key_size(kem_id);
    if (pk_len < 0 || sk_len < 0) {
        fprintf(stderr, "非法 kem_id\n");
        return 1;
    }
    uint8_t *pk = (uint8_t *)malloc((size_t)pk_len);
    uint8_t *sk = (uint8_t *)malloc((size_t)sk_len);
    if (pk == NULL || sk == NULL) {
        fprintf(stderr, "内存分配失败\n");
        return 1;
    }
    if (rzp2_kem_keygen(kem_id, pk, sk) != 0) {
        fprintf(stderr, "密钥生成失败\n");
        return 1;
    }

    /* 2) 混合加密（ML-KEM + ChaCha20-Poly1305）。 */
    const intptr_t need = rzp2_crypto_encrypt(kem_id, pk, (size_t)pk_len,
                                              (const uint8_t *)msg, msg_len, NULL, 0);
    if (need < 0) {
        fprintf(stderr, "查询密文大小失败\n");
        return 1;
    }
    uint8_t *ct = (uint8_t *)malloc((size_t)need);
    const intptr_t ct_len = rzp2_crypto_encrypt(kem_id, pk, (size_t)pk_len,
                                                (const uint8_t *)msg, msg_len,
                                                ct, (size_t)need);
    if (ct_len < 0) {
        fprintf(stderr, "加密失败\n");
        return 1;
    }
    printf("混合加密: %zu 字节明文 -> %" PRIdPTR " 字节密文\n", msg_len, ct_len);

    /* 3) 混合解密。 */
    const intptr_t pt_need = rzp2_crypto_decrypt(kem_id, sk, (size_t)sk_len,
                                                 ct, (size_t)ct_len, NULL, 0);
    if (pt_need < 0) {
        fprintf(stderr, "查询明文大小失败\n");
        return 1;
    }
    uint8_t *pt = (uint8_t *)malloc((size_t)pt_need + 1);
    const intptr_t pt_len = rzp2_crypto_decrypt(kem_id, sk, (size_t)sk_len,
                                                ct, (size_t)ct_len, pt, (size_t)pt_need);
    if (pt_len < 0) {
        fprintf(stderr, "解密失败（密钥错误或数据被篡改）\n");
        return 1;
    }
    pt[pt_len] = '\0';
    printf("解密结果: %s\n", pt);
    printf("往返一致: %s\n",
           (pt_len == (intptr_t)msg_len && memcmp(pt, msg, msg_len) == 0) ? "是" : "否");

    /* 4) 纯 AEAD（ChaCha20-Poly1305，32 字节密钥 + 12 字节 nonce）。 */
    uint8_t key[32];
    uint8_t nonce[12];
    memset(key, 0x42, sizeof(key));
    memset(nonce, 0x24, sizeof(nonce));
    const char *aad = "关联数据（可选）";

    const intptr_t a_need = rzp2_aead_encrypt(key, nonce, (const uint8_t *)msg, msg_len,
                                              (const uint8_t *)aad, strlen(aad), NULL, 0);
    uint8_t *a_ct = (uint8_t *)malloc((size_t)a_need);
    const intptr_t a_ct_len = rzp2_aead_encrypt(key, nonce, (const uint8_t *)msg, msg_len,
                                                (const uint8_t *)aad, strlen(aad),
                                                a_ct, (size_t)a_need);
    uint8_t *a_pt = (uint8_t *)malloc(msg_len + 1);
    const intptr_t a_pt_len = rzp2_aead_decrypt(key, nonce, a_ct, (size_t)a_ct_len,
                                                (const uint8_t *)aad, strlen(aad),
                                                a_pt, msg_len);
    if (a_pt_len < 0) {
        fprintf(stderr, "AEAD 解密失败\n");
        return 1;
    }
    a_pt[a_pt_len] = '\0';
    printf("AEAD 解密结果: %s\n", a_pt);

    free(pk);
    free(sk);
    free(ct);
    free(pt);
    free(a_ct);
    free(a_pt);
    return 0;
}
