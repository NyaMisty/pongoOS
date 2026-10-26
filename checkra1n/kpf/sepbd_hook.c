/*
 * pongoOS - https://checkra.in
 *
 * Copyright (C) 2026 NyaMisty
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER SOFTWARE
 * DEALINGS IN THE SOFTWARE.
 *
 * sepbd_hook: kernel side of the scheme C SEP backdoor.
 *
 * Hooks the AppleSEPKeyStore user-client selector dispatch for the private
 * selector 0x7BC — the same selector the SEOS-side handler (installed by the
 * sepbd sepfw hook at reload_sepi time) answers through the SKS workloop.
 *
 * The dispatch classifies selectors into families (<0x1A, 0xAA-0xAC, <=0xEA,
 * 0x83A) and walks a descriptor table for everything else; unknown selectors
 * fail kIOReturnNotPermitted. 0x7BC sits outside every family, so nothing
 * stock can collide with it. The hook is a front door in front of the
 * descriptor walk: gate on w1 == 0x7BC, else replay the displaced selector
 * load and jump back (byte-identical stock path).
 *
 * Anchors, re-derived per kernelcache (validated on iPad 7 / 18.6.2 22G100,
 * classic prelink layout — the AKS kext lives in __PLK_TEXT_EXEC; also
 * validated on the vphone600 cloudOS kernel where the same anchors resolve
 * in the fileset __TEXT_EXEC):
 *
 *   1. The failure-format literal "operation %s(sel: %d ret: %x%s)%s\n" —
 *      every failed selector print references it. Exactly one ADRP+ADD xref
 *      in the kext text.
 *   2. The dispatch function = the function containing that xref. Within it,
 *      the selector copy `mov wN, w1` (ORR alias, Rm=w1, imm6=0, Rn=WZR;
 *      same encoding 2a0103f3 observed on both kernels).
 *   3. The shared epilogue: `ldp x29, x30, [sp, #imm]` followed by the frame
 *      return within 0x40 bytes — plain `ret` on arm64 (A10), `retab` on
 *      arm64e. The success path branches there so the frame unwinds exactly
 *      like a stock return (a bare ret/retab from a cave leaks the frame and
 *      deadlocks the kernel — both observed live on the vphone VM).
 *   4. The cave: a run of >= 0x60 zero/0xffffffff/UDF words in the same
 *      segment, after the kext's text (used ones nearby; also fine farther).
 *
 * Trampoline layout (7 words): movz w8,#0x7BC; cmp w1,w8; b.ne replay;
 * mov x0,#0 (kIOReturnSuccess); b epilogue; <replay>; b back.
 */

#include "kpf.h"
#include <pongo.h>
#include <xnu/xnu.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define SEP_BD_SELECTOR 0x7BCu

static const char sepbd_fmt[] = "operation %s(sel: %d ret: %x%s";

// Branch encoders (same style as the other kpf patchers).
static uint32_t sepbd_b(int64_t delta_words)
{
    return 0x14000000u | ((uint32_t)delta_words & 0x03ffffffu);
}
static uint32_t sepbd_bne(int64_t delta_words)
{
    return 0x54000001u | (((uint32_t)delta_words & 0x7ffffu) << 5);
}

static bool sepbd_hook_fired = false;

static bool kpf_sepbd_callback(struct xnu_pf_patch *patch, void *opcode_stream_v)
{
    if(sepbd_hook_fired)
    {
        return false;
    }
    uint32_t *opcode_stream = (uint32_t *)opcode_stream_v;

    // opcode_stream[0..1] = the matched ADRP+ADD pair referencing the failure
    // literal; verify the literal before trusting the site.
    uint32_t adrp = opcode_stream[0],
             add  = opcode_stream[1];
    const char *str = (const char *)(((uint64_t)(opcode_stream) & ~0xfffULL) + adrp_off(adrp) + ((add >> 10) & 0xfff));
    // The literal begins before the referenced point (prefix log fields); walk
    // back to the string start, then require the failure format within it.
    while(str != (const char *)((uint64_t)opcode_stream & ~0xfffULL) && str[-1] != '\0')
    {
        --str;
    }
    size_t fmt_len = sizeof(sepbd_fmt) - 1;
    if(!(strlen(str) >= fmt_len && strstr(str, sepbd_fmt) != NULL))
    {
        return false;
    }

    // The dispatch function starts before the xref; scan back for the frame
    // prologue's stp x29, x30 (any [sp,#imm] addressing).
    uint32_t *fn = opcode_stream;
    for(int i = 0; i < 0x200; ++i, --fn)
    {
        uint32_t w = *fn;
        // stp x29, x30, [sp, #imm] / [sp, #-imm]! — LDP-family with Rt=x29,Rt2=x30
        if((w & 0xffc003ff) == 0xa90003fd || w == 0xa9bf7bfd)
        {
            break;
        }
    }
    // (If nothing found, fn walked 0x200 back — the scan below still works on
    // a generous window; the selector/epilogue shapes are distinctive enough.)

    uint32_t *sel = NULL, *epilogue = NULL;
    for(uint32_t *p = fn; p < fn + 0x400; ++p)
    {
        // mov wN, w1 — ORR shifted-register alias: Rm=w1(1), imm6=0, Rn=WZR(31).
        if(!sel && (*p & 0xffffffe0) == 0x2a0103e0)
        {
            sel = p;
        }
        // ldp x29, x30, [sp, #imm]
        if((*p & 0xffc003ff) == 0xa94003fd)
        {
            uint32_t *q = p + 1;
            for(uint32_t d = 0; d < 0x10; ++d, ++q)
            {
                if(*q == 0xd65f03c0 || *q == 0xd65f0fff) // ret / retab
                {
                    epilogue = p;
                    break;
                }
                if((*q & 0x7c000000) == 0x14000000) // branch out: not the shared tail
                {
                    break;
                }
            }
        }
        if(sel && epilogue && epilogue > sel)
        {
            break;
        }
    }
    if(!sel || !epilogue)
    {
        DEVLOG("sepbd_hook: selector/epilogue not found (sel=%p epi=%p)", sel, epilogue);
        return false;
    }

    // Cave: >= 0x60 dead words AFTER the kext's own text in the same segment.
    // Search forward from the epilogue; the segment extends far past it.
    uint32_t *cave = NULL;
    uint32_t dead_run = 0;
    for(uint32_t *p = epilogue; p < epilogue + 0x100000; ++p)
    {
        uint32_t w = *p;
        if(w == 0x00000000u || w == 0xffffffffu || w == 0xd4200000u)
        {
            if(++dead_run >= 0x60)
            {
                cave = p - 0x5f;
                break;
            }
        }
        else
        {
            dead_run = 0;
        }
    }
    if(!cave)
    {
        DEVLOG("sepbd_hook: no code cave found");
        return false;
    }

    // Gate + replay + epilogue-unwind trampoline. Success path returns
    // kIOReturnSuccess through the function's own epilogue; everything else
    // falls through to the stock dispatch untouched.
    uint32_t replay = *sel;
    int64_t cave_off = cave - sel;
    int64_t back_off = (sel + 1) - (cave + 6);
    int64_t epi_off  = epilogue - (cave + 4);
    int64_t replay_off = (cave + 5) - (cave + 2);

    cave[0] = 0x52800008u | (SEP_BD_SELECTOR << 5); // movz w8, #0x7BC
    cave[1] = 0x6b08003fu;                          // cmp w1, w8
    cave[2] = sepbd_bne(replay_off);                // b.ne replay_slot
    cave[3] = 0xd2800000u;                          // mov x0, #0 (kIOReturnSuccess)
    cave[4] = sepbd_b(epi_off);                     // b <dispatch epilogue>
    cave[5] = replay;                               // displaced `mov wN, w1`
    cave[6] = sepbd_b(back_off);                    // b sel+1 (stock path)

    *sel = sepbd_b(cave_off);                       // b cave

    sepbd_hook_fired = true;
    DEVLOG("sepbd_hook: sel @ %p -> cave @ %p, epilogue @ %p",
           xnu_ptr_to_va(sel), xnu_ptr_to_va(cave), xnu_ptr_to_va(epilogue));
    return false; // keep scanning other matches harmlessly
}

static void kpf_sepbd_patches(xnu_pf_patchset_t *aks_text_exec_patchset)
{
    if(!sepbd_hook_fired)
    {
        // ADRP+ADD pair; the callback verifies the pointed-to literal itself.
        uint64_t match[] = { 0x90000010u, 0x91000010u };
        uint64_t mask[]  = { 0x9f00001fu, 0xffc003ffu };
        // rd of ADRP is unconstrained but must match rn of ADD: the patchfinder
        // cannot express that cross-instruction constraint, so accept any pair
        // and validate in the callback (string compare filters false positives).
        xnu_pf_maskmatch(aks_text_exec_patchset, "sepbd_dispatch_xref", match, mask, 2, false, kpf_sepbd_callback);
    }
}

kpf_component_t kpf_sepbd_hook =
{
    .patches =
    {
        { "com.apple.driver.AppleSEPKeyStore", "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_sepbd_patches },
        {},
    },
};
