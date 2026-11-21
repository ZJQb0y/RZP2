#ifndef RZP2_COMPRESS_H
#define RZP2_COMPRESS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * RZP2 压缩 / 解压动态库（LZMA1 "alone" 格式，与 LZMA SDK / xz 兼容）。
 *
 * 返回码约定：
 *   >= 0  成功（压缩/解压为写出字节数；查询容量时为所需字节数）
 *   -1    参数错误 / 数据损坏
 *   -2    输出缓冲区不足
 */

/* ABI 版本号（当前为 1）。 */
uint32_t rzp2_compress_version(void);

/*
 * LZMA1 alone 压缩。level 0..=9（越界按 9 处理）。
 * out 传 NULL 时返回所需缓冲区字节数（不写入）；
 * 否则写入压缩结果并返回写出字节数，out_cap 不足返回 -2。
 */
intptr_t rzp2_compress(const uint8_t *input, size_t input_len, uint32_t level,
                       uint8_t *out, size_t out_cap);

/* 从 LZMA1 alone 头部读取未压缩长度；未知或非法返回 -1。 */
intptr_t rzp2_decompressed_size(const uint8_t *input, size_t input_len);

/*
 * LZMA1 alone 解压。
 * out 传 NULL 时返回所需缓冲区字节数（不写入）；
 * 否则写入明文并返回写出字节数；数据损坏返回 -1，out_cap 不足返回 -2。
 */
intptr_t rzp2_decompress(const uint8_t *input, size_t input_len,
                         uint8_t *out, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif /* RZP2_COMPRESS_H */
