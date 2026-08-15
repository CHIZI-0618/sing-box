// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SING_BOX_EBPF_PRIVATE_ADDRESS_H
#define SING_BOX_EBPF_PRIVATE_ADDRESS_H

#include <linux/types.h>
#include <stdbool.h>

static __attribute__((always_inline)) bool sb_ebpf_ipv4_private_address(const __u8 address[4]) {
    if (address[0] == 0U || address[0] == 10U || address[0] == 127U || address[0] >= 224U) return true;
    if (address[0] == 100U && (address[1] & 0xc0U) == 0x40U) return true;
    if (address[0] == 169U && address[1] == 254U) return true;
    if (address[0] == 172U && (address[1] & 0xf0U) == 0x10U) return true;
    return address[0] == 192U && address[1] == 168U;
}

static __attribute__((always_inline)) bool sb_ebpf_ipv6_private_address(const __u8 address[16]) {
    if (address[0] == 0xffU || (address[0] & 0xfeU) == 0xfcU) return true;
    return address[0] == 0xfeU && (address[1] & 0xc0U) == 0x80U;
}

#endif
