/*
 * RZP2 压缩/解压动态库使用示例（C）。
 *
 * 编译（Linux，链接 .so）：
 *   gcc -o compress_demo examples/ffi/rzp2_compress_demo.c \
 *       -Icrates/rzp2-compress/include -Ltarget/release -lrzp2_compress \
 *       -Wl,-rpath,target/release
 *
 * Windows（MinGW，链接 .dll）：
 *   gcc -o compress_demo.exe examples/ffi/rzp2_compress_demo.c \
 *       -Icrates/rzp2-compress/include -Ltarget/release -lrzp2_compress
 *   （运行前把 rzp2_compress.dll 放到 exe 同目录或 PATH 中）
 */
#include "rzp2_compress.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    const char *text = "Hello, RZP2! 这是一段用于演示 LZMA 压缩/解压的文本。";
    const size_t in_len = strlen(text);

    /* 1) 查询压缩后所需缓冲区大小（out 传 NULL，不写入）。 */
    const intptr_t need = rzp2_compress((const uint8_t *)text, in_len, 6, NULL, 0);
    if (need < 0) {
        fprintf(stderr, "查询压缩大小失败\n");
        return 1;
    }

    uint8_t *compressed = (uint8_t *)malloc((size_t)need);
    if (compressed == NULL) {
        fprintf(stderr, "内存分配失败\n");
        return 1;
    }
    const intptr_t clen = rzp2_compress((const uint8_t *)text, in_len, 6,
                                        compressed, (size_t)need);
    if (clen < 0) {
        fprintf(stderr, "压缩失败\n");
        free(compressed);
        return 1;
    }
    printf("原始 %zu 字节 -> 压缩 %" PRIdPTR " 字节\n", in_len, clen);

    /* 2) 从 LZMA1 头部读取未压缩长度。 */
    const intptr_t out_len = rzp2_decompressed_size(compressed, (size_t)clen);
    if (out_len < 0) {
        fprintf(stderr, "读取未压缩长度失败\n");
        free(compressed);
        return 1;
    }

    /* 3) 解压（out 传 NULL 查询容量，此处直接按 out_len 分配）。 */
    uint8_t *plain = (uint8_t *)malloc((size_t)out_len + 1);
    if (plain == NULL) {
        fprintf(stderr, "内存分配失败\n");
        free(compressed);
        return 1;
    }
    const intptr_t plain_len = rzp2_decompress(compressed, (size_t)clen,
                                               plain, (size_t)out_len);
    if (plain_len < 0) {
        fprintf(stderr, "解压失败\n");
        free(compressed);
        free(plain);
        return 1;
    }
    plain[plain_len] = '\0';

    printf("解压结果: %s\n", plain);
    printf("往返一致: %s\n",
           (plain_len == (intptr_t)in_len && memcmp(plain, text, in_len) == 0) ? "是"
                                                                               : "否");

    free(compressed);
    free(plain);
    return 0;
}
