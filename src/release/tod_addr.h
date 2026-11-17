/*
 * tod_addr.h: the game's code addresses for the release this build is made from.
 *
 * The port names the game's functions and code addresses by their BCES00052 1.00 (EU) address. The build
 * picks a release (CMake TOD_RELEASE) and tools/tod_release.cmake writes gen/tod_release.h from
 * versions/addresses.tsv, which maps every such address to the release's own. With BCES00052 every name below
 * is exactly what it was before (func_00597328, 0x00597328u, ...).
 *
 *   TOD_FUNC(00597328)          the lifted function at EU 0x00597328 in this release (func_<addr>)
 *   TOD_ADDR(006F1BA0)          the guest address itself, as a uint32_t constant
 *   TOD_HOOK(ASPECT_PROJECTION) a hook by its role (versions/addresses.tsv, column "role"): func_<addr>
 *   TOD_HOOK_LIFTED(ROLE)       the hook's lifted body, renamed func_<addr>_lifted by tools/tod_release.cmake
 *
 * An address that is not in the table does not compile (TOD_A_<eu> undefined), so a new reference has to be
 * added there, with each release's value, first.
 */
#pragma once
#include <stdint.h>
#include "tod_release.h"   /* gen/: TOD_A_<eu>, TOD_H_<role>, TOD_RELEASE_ID */

#define TOD__CAT_(a, b) a##b
#define TOD__CAT(a, b)  TOD__CAT_(a, b)

#define TOD_FUNC(eu)           TOD__CAT(func_, TOD_A_##eu)
#define TOD_LIFTED(eu)         TOD__CAT(TOD__CAT(func_, TOD_A_##eu), _lifted)
#define TOD_ADDR(eu)           ((uint32_t)TOD__CAT(0x, TOD_A_##eu))
#define TOD_HOOK(role)         TOD__CAT(func_, TOD_H_##role)
#define TOD_HOOK_LIFTED(role)  TOD__CAT(TOD__CAT(func_, TOD_H_##role), _lifted)
