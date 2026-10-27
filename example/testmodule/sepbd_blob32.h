#ifndef SEPBD_BLOB32_H
#define SEPBD_BLOB32_H
#include <stdint.h>
// ARM32 handler for the A10 (T8010) blackbird dispatcher — the dispatcher stub
// runs in AArch32, so the payload must be 32-bit code. Ping-only first cut.
static const uint32_t k_sepbd_blob32[23] = {
    0xe5901004u, 0xe59f2048u, 0xe1510002u, 0x1a00000eu, 0xe590300cu, 0xe30027bcu,
    0xe1530002u, 0x1a00000au, 0xe5901000u, 0xe3510001u, 0x1a000007u, 0xe3a02000u,
    0xe5802000u, 0xe59f201cu, 0xe5802004u, 0xe5902010u, 0xe5802008u, 0xe3a00000u,
    0xe12fff1eu, 0xe3e00000u, 0xe12fff1eu, 0x44504256u, 0x52504456u,
};
#define SEP_BD_BLOB32_WORDS 23
#endif
