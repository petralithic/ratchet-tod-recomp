/*
 * decrypt_fps.cpp (17/11) -- TOD_DECRYPT_FPS: the decrypter (hacking) minigame runs at 60 fps.
 *
 * GitHub issue #30: above 60 fps the decrypter's ball does not move; at 60 it works. The minigame's per-frame step is
 * func_003B7AA8 (one caller, the minigame update func_003B8998 at 0x3B95B8; it runs the ball physics func_003B5EC0).
 * tools/tod_release.cmake renames the lifted definition to func_003B7AA8_lifted; this file
 * provides func_003B7AA8, which only stamps the time and calls it. main.cpp (decrypt_fps_poll) puts the FPS limit at 60
 * while the stamp is younger than 300 ms and the player's TOD_FPS is above 60, and gives the player's limit back after.
 *
 * TOD_DECRYPT_FPS = 1 on, unset or 0 off (code default off; the packages turn it on in tod.ini).
 */
#include "ppu_recomp.h"
#include "release/tod_addr.h"   /* this release's code addresses (versions/addresses.tsv) */

#define WIN32_LEAN_AND_MEAN
#include "platform/tod_platform.h"   /* <windows.h> on Windows */

void TOD_HOOK_LIFTED(DECRYPT_STEP)(ppu_context* ctx);

extern "C" volatile unsigned long long g_tod_decrypt_tick = 0;   // GetTickCount64 of the last minigame step, read by main.cpp

void TOD_HOOK(DECRYPT_STEP)(ppu_context* ctx)
{
    g_tod_decrypt_tick = GetTickCount64();
    TOD_HOOK_LIFTED(DECRYPT_STEP)(ctx);
}
