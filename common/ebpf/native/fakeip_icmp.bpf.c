// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// This object answers ICMP Echo Request packets destined to the configured
// FakeIP prefixes with a locally synthesized Echo Reply, so a client's ping
// tool sees the FakeIP address as reachable without the request ever leaving
// this box. It is deliberately independent of tc.bpf.c: it needs no socket
// lookup, no sk_assign, no SOCKMAP, and no delivery veth, because there is no
// listener to hand the packet to — the reply is built in place and bounced
// straight back the way it came.
//
// Parsing is limited to a subset that is fully bounds-checked and has a test
// for every accept/pass-through decision: IPv4 with no options and no
// fragmentation, IPv6 with no extension header in front of ICMPv6. Anything
// else — including anything truncated enough that it cannot be read safely —
// falls through unmodified (TC_ACT_UNSPEC), the same convention every parser
// in this codebase already follows.

#include "bpf_compat.h"
#include "fakeip_policy.h"

#include <linux/bpf.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_UNSPEC (-1)

#define BPF_F_INGRESS (1ULL << 0)
#define BPF_F_PSEUDO_HDR (1ULL << 4)

#define ETH_P_IP_VALUE 0x0800U
#define ETH_P_IPV6_VALUE 0x86ddU
#define ETH_P_8021Q_VALUE 0x8100U
#define ETH_P_8021AD_VALUE 0x88a8U

#define IPPROTO_ICMP_VALUE 1U
#define IPPROTO_ICMPV6_VALUE 58U

#define IPV4_FRAGMENT_OFFSET_MASK 0x1fffU
#define IPV4_FRAGMENT_MORE 0x2000U

#define ICMP_ECHO_REQUEST_VALUE 8U
#define ICMP_ECHO_REPLY_VALUE 0U
#define ICMPV6_ECHO_REQUEST_VALUE 128U
#define ICMPV6_ECHO_REPLY_VALUE 129U

#define SB_FAKEIP_ICMP_FLAG_ENABLED (1U << 0)
#define SB_FAKEIP_ICMP_FLAG_IPV4 (1U << 1)
#define SB_FAKEIP_ICMP_FLAG_LOCAL_IPV6 (1U << 2)
#define SB_FAKEIP_ICMP_FLAG_SHARED_IPV6 (1U << 3)
#define SB_FAKEIP_ICMP_FLAG_FAKEIP_IPV4 (1U << 4)
#define SB_FAKEIP_ICMP_FLAG_FAKEIP_IPV6 (1U << 5)

// Independent of sb_tc_control by design: this object only ever needs the
// address-family toggles and the FakeIP prefixes themselves, not the rest of
// the TC data plane's policy surface.
struct sb_fakeip_icmp_control {
    __u32 flags;
    __u8 fakeip_ipv4_prefix[4];
    __u8 fakeip_ipv4_mask[4];
    __u8 fakeip_ipv6_prefix[16];
    __u8 fakeip_ipv6_mask[16];
};

_Static_assert(sizeof(struct sb_fakeip_icmp_control) == 44, "sb_fakeip_icmp_control ABI size");
_Static_assert(__builtin_offsetof(struct sb_fakeip_icmp_control, fakeip_ipv6_mask) == 28,
    "sb_fakeip_icmp_control fakeip_ipv6_mask ABI offset");

struct ethernet_header {
    __u8 destination[6];
    __u8 source[6];
    __be16 protocol;
};

struct vlan_header {
    __be16 tci;
    __be16 protocol;
};

struct ipv4_header {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    __u8 ihl : 4;
    __u8 version : 4;
#else
    __u8 version : 4;
    __u8 ihl : 4;
#endif
    __u8 tos;
    __be16 total_length;
    __be16 id;
    __be16 fragment_offset;
    __u8 ttl;
    __u8 protocol;
    __sum16 checksum;
    __be32 source;
    __be32 destination;
};

struct ipv6_header {
    __be32 version_flow;
    __be16 payload_length;
    __u8 next_header;
    __u8 hop_limit;
    __u8 source[16];
    __u8 destination[16];
};

// type, code, checksum, identifier, sequence — the fixed part of both ICMP
// and ICMPv6 echo messages. The payload that follows is never read: nothing
// here needs it, and not reading it is what keeps the reply's length exactly
// equal to the request's.
struct icmp_echo_header {
    __u8 type;
    __u8 code;
    __sum16 checksum;
    __be16 identifier;
    __be16 sequence;
};

#define MAP(name, key, value, map_type, entries) \
    struct bpf_map_def SEC("maps") name = { \
        .type = map_type, .key_size = sizeof(key), .value_size = sizeof(value), \
        .max_entries = entries, \
    }

MAP(fakeip_icmp_control, __u32, struct sb_fakeip_icmp_control, BPF_MAP_TYPE_ARRAY, 1U);

// fakeip_icmp_stats counts three outcomes for this object's own decisions,
// distinct from any counter tc.bpf.c or shared_network.bpf.c keeps: a reply
// actually sent, an ICMP Echo Request this object examined but did not
// answer because it fell outside the safe subset (fragmented, has options,
// wrong type/code, an extension header, or a destination outside the FakeIP
// prefixes), and an in-place rewrite that failed partway (dropped, not
// passed through, since the packet is already partially mutated by then).
// Traffic that is not ICMP/ICMPv6 to begin with is not counted here at all
// -- that would just be a count of ordinary traffic on whatever interface
// this program is attached to, not a fact about fakeip_icmp's own behavior.
#define SB_FAKEIP_ICMP_STAT_REPLY 0U
#define SB_FAKEIP_ICMP_STAT_PASS_THROUGH 1U
#define SB_FAKEIP_ICMP_STAT_REWRITE_FAILURE 2U
#define SB_FAKEIP_ICMP_STAT_COUNT 3U

MAP(fakeip_icmp_stats, __u32, __u64, BPF_MAP_TYPE_PERCPU_ARRAY, SB_FAKEIP_ICMP_STAT_COUNT);

static void *(*map_lookup)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*redirect)(int ifindex, __u64 flags) = (void *)BPF_FUNC_redirect;
static long (*skb_store_bytes)(void *ctx, __u32 offset, const void *from, __u32 length, __u64 flags) =
    (void *)BPF_FUNC_skb_store_bytes;
static long (*l3_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 size) =
    (void *)BPF_FUNC_l3_csum_replace;
static long (*l4_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 flags) =
    (void *)BPF_FUNC_l4_csum_replace;
static __s64 (*csum_diff)(const __be32 *from, __u32 from_size, const __be32 *to, __u32 to_size, __wsum seed) =
    (void *)BPF_FUNC_csum_diff;

INLINE void record_fakeip_icmp_stat(__u32 key) {
    __u64 *counter = map_lookup(&fakeip_icmp_stats, &key);
    if (counter != 0) *counter += 1U;
}

INLINE __u16 network_order16(__u16 value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap16(value);
#else
    return value;
#endif
}

INLINE __u32 network_order32(__be32 value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap32(value);
#else
    return value;
#endif
}

INLINE const struct sb_fakeip_icmp_control *load_control(void) {
    __u32 zero = 0U;
    return map_lookup(&fakeip_icmp_control, &zero);
}

INLINE bool parse_ethernet(void *data, void *data_end, __u16 *protocol, __u32 *l3_offset) {
    struct ethernet_header *ethernet = data;
    if ((void *)(ethernet + 1) > data_end) return false;
    *protocol = network_order16(ethernet->protocol);
    *l3_offset = sizeof(*ethernet);
#pragma clang loop unroll(full)
    for (__u32 depth = 0U; depth < 2U; ++depth) {
        if (*protocol != ETH_P_8021Q_VALUE && *protocol != ETH_P_8021AD_VALUE) break;
        struct vlan_header *vlan = data + *l3_offset;
        if ((void *)(vlan + 1) > data_end) return false;
        *protocol = network_order16(vlan->protocol);
        *l3_offset += sizeof(*vlan);
    }
    return true;
}

// swap_ethernet_addresses exchanges the frame's source and destination MAC
// addresses in place. shared_reply uses this so the reflected reply is
// addressed back to the client that sent the request rather than toward
// whatever the request's own destination MAC was (this box's own interface).
// local_reply uses the same swap for a different reason: the frame's own
// source address, now in the destination field, is this device's own
// address, which is what lets the reinjected frame read as PACKET_HOST
// instead of PACKET_OTHERHOST once it re-enters this device's own receive
// path (see local_reply's own comment).
INLINE bool swap_ethernet_addresses(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethernet_header *ethernet = data;
    if ((void *)(ethernet + 1) > data_end) return false;
    __u8 old_destination[6];
    __u8 old_source[6];
    __builtin_memcpy(old_destination, ethernet->destination, 6U);
    __builtin_memcpy(old_source, ethernet->source, 6U);
    if (skb_store_bytes(skb, __builtin_offsetof(struct ethernet_header, destination), old_source, 6U, 0U) != 0 ||
        skb_store_bytes(skb, __builtin_offsetof(struct ethernet_header, source), old_destination, 6U, 0U) != 0) {
        return false;
    }
    return true;
}

// find_ipv4_echo_request accepts exactly the safe subset this object commits
// to: no IP options (ihl == 5, so the fixed 20-byte header is the whole IP
// header), not a fragment, protocol ICMP, and an Echo Request (type 8, code
// 0). Anything else is not this object's to answer, including anything the
// bounds checks cannot safely read — both are reported the same way, by
// returning false, because a caller that only ever passes the packet through
// on false has no way to tell "not for us" from "cannot be read" apart, and
// does not need to.
// find_ipv4_echo_request's own pass-through counting deliberately starts
// only after confirming the packet is ICMP at all: every disqualification
// before that point (not ICMP, or too short to even read the fixed header)
// would otherwise count ordinary TCP/UDP traffic on this interface, which is
// not a fact about fakeip_icmp's own behavior. Once a packet is known to be
// ICMP, every further disqualification -- options, fragmentation, wrong
// destination, wrong type/code, or too short to read the rest -- is exactly
// what SB_FAKEIP_ICMP_STAT_PASS_THROUGH exists to count.
INLINE bool find_ipv4_echo_request(void *data, void *data_end, __u32 packet_length, __u32 l3_offset,
    const struct sb_fakeip_icmp_control *control, struct ipv4_header **ip, struct icmp_echo_header **icmp) {
    struct ipv4_header *header = data + l3_offset;
    if ((void *)(header + 1) > data_end) return false;
    if (header->protocol != IPPROTO_ICMP_VALUE) return false;
    if (header->version != 4U || header->ihl != 5U) {
        record_fakeip_icmp_stat(SB_FAKEIP_ICMP_STAT_PASS_THROUGH);
        return false;
    }
    if ((network_order16(header->fragment_offset) & (IPV4_FRAGMENT_OFFSET_MASK | IPV4_FRAGMENT_MORE)) != 0U) {
        record_fakeip_icmp_stat(SB_FAKEIP_ICMP_STAT_PASS_THROUGH);
        return false;
    }
    __u16 total_length = network_order16(header->total_length);
    if (total_length < sizeof(*header) + sizeof(struct icmp_echo_header)) {
        record_fakeip_icmp_stat(SB_FAKEIP_ICMP_STAT_PASS_THROUGH);
        return false;
    }
    if (packet_length < l3_offset || (__u32)total_length > packet_length - l3_offset) {
        record_fakeip_icmp_stat(SB_FAKEIP_ICMP_STAT_PASS_THROUGH);
        return false;
    }
    __u8 destination[4];
    __builtin_memcpy(destination, &header->destination, 4U);
    if (!sb_ebpf_must_intercept_fakeip_ipv4(
            destination, control->flags, SB_FAKEIP_ICMP_FLAG_FAKEIP_IPV4,
            control->fakeip_ipv4_prefix, control->fakeip_ipv4_mask)) {
        record_fakeip_icmp_stat(SB_FAKEIP_ICMP_STAT_PASS_THROUGH);
        return false;
    }
    struct icmp_echo_header *echo = (void *)header + 20U;
    if ((void *)(echo + 1) > data_end) {
        record_fakeip_icmp_stat(SB_FAKEIP_ICMP_STAT_PASS_THROUGH);
        return false;
    }
    if (echo->type != ICMP_ECHO_REQUEST_VALUE || echo->code != 0U) {
        record_fakeip_icmp_stat(SB_FAKEIP_ICMP_STAT_PASS_THROUGH);
        return false;
    }
    *ip = header;
    *icmp = echo;
    return true;
}

// find_ipv6_echo_request commits to a narrower subset than the TC data
// plane's own IPv6 parser: next_header has to be ICMPv6 directly on the fixed
// 40-byte header, with no extension header in front of it at all. A hop-by-
// hop or routing header ahead of a real echo request is passed through
// unmodified rather than walked, which is the conservative half of "either
// explicitly allow or explicitly drop, never parse past what is verified".
// Pass-through counting starts only once next_header is confirmed to be
// ICMPv6 -- see find_ipv4_echo_request's own comment on why "not this
// protocol at all" and "this protocol, but disqualified" are not the same
// thing to count.
INLINE bool find_ipv6_echo_request(void *data, void *data_end, __u32 packet_length, __u32 l3_offset,
    const struct sb_fakeip_icmp_control *control, struct ipv6_header **ip, struct icmp_echo_header **icmp) {
    struct ipv6_header *header = data + l3_offset;
    if ((void *)(header + 1) > data_end) return false;
    if (header->next_header != IPPROTO_ICMPV6_VALUE) return false;
    if ((network_order32(header->version_flow) >> 28U) != 6U) {
        record_fakeip_icmp_stat(SB_FAKEIP_ICMP_STAT_PASS_THROUGH);
        return false;
    }
    __u16 payload_length = network_order16(header->payload_length);
    if (payload_length < sizeof(struct icmp_echo_header)) {
        record_fakeip_icmp_stat(SB_FAKEIP_ICMP_STAT_PASS_THROUGH);
        return false;
    }
    if (packet_length < l3_offset || (__u32)payload_length + sizeof(*header) > packet_length - l3_offset) {
        record_fakeip_icmp_stat(SB_FAKEIP_ICMP_STAT_PASS_THROUGH);
        return false;
    }
    if (!sb_ebpf_must_intercept_fakeip_ipv6(
            header->destination, control->flags, SB_FAKEIP_ICMP_FLAG_FAKEIP_IPV6,
            control->fakeip_ipv6_prefix, control->fakeip_ipv6_mask)) {
        record_fakeip_icmp_stat(SB_FAKEIP_ICMP_STAT_PASS_THROUGH);
        return false;
    }
    struct icmp_echo_header *echo = (void *)header + sizeof(*header);
    if ((void *)(echo + 1) > data_end) {
        record_fakeip_icmp_stat(SB_FAKEIP_ICMP_STAT_PASS_THROUGH);
        return false;
    }
    if (echo->type != ICMPV6_ECHO_REQUEST_VALUE || echo->code != 0U) {
        record_fakeip_icmp_stat(SB_FAKEIP_ICMP_STAT_PASS_THROUGH);
        return false;
    }
    *ip = header;
    *icmp = echo;
    return true;
}

// reply_ipv4_echo turns an Echo Request into an Echo Reply in place: swap
// source and destination, flip the ICMP type, and nothing else. Neither the
// identifier, the sequence, nor the payload is ever read or written, which is
// what keeps the reply exactly as long as the request — it cannot be an
// amplification vector because it can never be larger than what arrived.
//
// Everything this needs from the packet is read by the caller before any
// helper that can change packet data runs, and passed in here as plain
// values rather than pointers: the verifier invalidates pointers derived from
// skb->data/data_end across a data-changing helper call (skb_store_bytes
// included), so a pointer read before one and dereferenced after it is
// exactly the access this function must not make, whether or not the
// underlying buffer actually moved.
//
// The IP header checksum is a plain sum over the header's 16-bit words, so
// swapping two of those words does not change the sum in principle — but the
// swap still goes through l3_csum_replace once per field, with the real
// before/after values, rather than skipping the call on that assumption. The
// same two calls also keep the skb's own checksum-complete bookkeeping
// consistent with the bytes actually written, which a value that merely
// happens to net to zero would not do on its own.
//
// The ICMP checksum has no pseudo-header for IPv4 — it depends only on the
// ICMP message itself — so the address swap needs no update there at all;
// only the type field's checksum contribution changes, patched with the
// known old and new 16-bit type+code word.
//
// That word is assembled with a byte copy rather than a host-order shift
// (type << 8 | code): l3_csum_replace/l4_csum_replace treat "from"/"to" as
// the field's raw on-the-wire bytes, the same convention old_port/new_port
// already rely on elsewhere in this codebase without any ntohs/htons
// applied. A shift bakes in one specific byte order, which only matches one
// of the two endianness targets this same source is compiled for (bpfel and
// bpfeb) — the other silently gets a checksum patched against a byte-swapped
// word, valid-looking to the compiler but wrong on the wire.
INLINE int reply_ipv4_echo(struct __sk_buff *skb, __u32 l3_offset, __be32 old_source, __be32 old_destination, __u8 old_type, __u8 old_code) {
    __be32 new_source = old_destination;
    __be32 new_destination = old_source;
    __u32 source_offset = l3_offset + __builtin_offsetof(struct ipv4_header, source);
    __u32 destination_offset = l3_offset + __builtin_offsetof(struct ipv4_header, destination);
    __u32 checksum_offset = l3_offset + __builtin_offsetof(struct ipv4_header, checksum);
    __u32 icmp_offset = l3_offset + 20U;
    __u8 new_type = (__u8)ICMP_ECHO_REPLY_VALUE;
    __u8 old_type_code_bytes[2] = {old_type, old_code};
    __u8 new_type_code_bytes[2] = {new_type, old_code};
    __u16 old_type_code;
    __u16 new_type_code;
    __builtin_memcpy(&old_type_code, old_type_code_bytes, 2U);
    __builtin_memcpy(&new_type_code, new_type_code_bytes, 2U);
    __u32 icmp_checksum_offset = icmp_offset + __builtin_offsetof(struct icmp_echo_header, checksum);
    if (l3_csum_replace(skb, checksum_offset, old_source, new_source, 4U) != 0 ||
        l3_csum_replace(skb, checksum_offset, old_destination, new_destination, 4U) != 0 ||
        l4_csum_replace(skb, icmp_checksum_offset, old_type_code, new_type_code, 2U) != 0 ||
        skb_store_bytes(skb, source_offset, &new_source, 4U, 0U) != 0 ||
        skb_store_bytes(skb, destination_offset, &new_destination, 4U, 0U) != 0 ||
        skb_store_bytes(skb, icmp_offset + __builtin_offsetof(struct icmp_echo_header, type), &new_type, 1U, 0U) != 0) {
        record_fakeip_icmp_stat(SB_FAKEIP_ICMP_STAT_REWRITE_FAILURE);
        return TC_ACT_SHOT;
    }
    record_fakeip_icmp_stat(SB_FAKEIP_ICMP_STAT_REPLY);
    return TC_ACT_OK;
}

// reply_ipv6_echo is the IPv6 mirror of reply_ipv4_echo, with the same
// pointer-lifetime rule: old_addresses is a byte-for-byte copy the caller
// took before any data-changing helper ran, not a pointer into the packet.
// IPv6 has no header checksum of its own, but ICMPv6's checksum does cover a
// pseudo-header of source, destination, length and next-header (RFC 4443),
// so the address swap's effect there is patched the same way
// shared_network_rewrite.h's rewrite_ipv6 patches an address change: a diff
// over the whole 32-byte {source, destination} block, computed from the real
// before/after bytes rather than assumed to net to zero.
INLINE int reply_ipv6_echo(struct __sk_buff *skb, __u32 l3_offset, const __u8 old_addresses[32], __u8 old_type, __u8 old_code) {
    __u8 new_addresses[32];
    __builtin_memcpy(new_addresses, old_addresses + 16U, 16U);
    __builtin_memcpy(new_addresses + 16U, old_addresses, 16U);
    __u32 source_offset = l3_offset + __builtin_offsetof(struct ipv6_header, source);
    __u32 icmp_offset = l3_offset + sizeof(struct ipv6_header);
    __u8 new_type = (__u8)ICMPV6_ECHO_REPLY_VALUE;
    // See reply_ipv4_echo: a byte copy, not a host-order shift, so the same
    // source compiles correctly for both the bpfel and bpfeb targets.
    __u8 old_type_code_bytes[2] = {old_type, old_code};
    __u8 new_type_code_bytes[2] = {new_type, old_code};
    __u16 old_type_code;
    __u16 new_type_code;
    __builtin_memcpy(&old_type_code, old_type_code_bytes, 2U);
    __builtin_memcpy(&new_type_code, new_type_code_bytes, 2U);
    __u32 icmp_checksum_offset = icmp_offset + __builtin_offsetof(struct icmp_echo_header, checksum);
    __s64 address_diff = csum_diff((const __be32 *)old_addresses, 32U, (const __be32 *)new_addresses, 32U, 0U);
    if (address_diff < 0) { record_fakeip_icmp_stat(SB_FAKEIP_ICMP_STAT_REWRITE_FAILURE); return TC_ACT_SHOT; }
    if (l4_csum_replace(skb, icmp_checksum_offset, 0U, (__u64)address_diff, BPF_F_PSEUDO_HDR) != 0 ||
        l4_csum_replace(skb, icmp_checksum_offset, old_type_code, new_type_code, 2U) != 0 ||
        skb_store_bytes(skb, source_offset, new_addresses, 32U, 0U) != 0 ||
        skb_store_bytes(skb, icmp_offset + __builtin_offsetof(struct icmp_echo_header, type), &new_type, 1U, 0U) != 0) {
        record_fakeip_icmp_stat(SB_FAKEIP_ICMP_STAT_REWRITE_FAILURE);
        return TC_ACT_SHOT;
    }
    record_fakeip_icmp_stat(SB_FAKEIP_ICMP_STAT_REPLY);
    return TC_ACT_OK;
}

// local_reply runs at TC egress on the local interface, the same attachment
// local_egress_mark uses, as a second and fully independent filter: turning
// fakeip_icmp off leaves that filter and everything it does untouched.
//
// A match never reaches the wire and never reaches the delivery veth. It is
// answered here, in place, and bounced back with bpf_redirect(ifindex,
// BPF_F_INGRESS) — the same device's own receive path, so the reply is
// delivered to the pinging socket exactly as a genuine incoming reply would
// be, without a socket lookup or an sk_assign ever entering into it.
//
// On an Ethernet-framed interface, the redirected frame is re-classified by
// eth_type_trans on the way back into this device's own receive path, which
// compares the frame's destination address against the device's own address
// to decide pkt_type: PACKET_HOST if they match, PACKET_OTHERHOST otherwise.
// The original request's destination was the far side's address (this device
// was only ever transmitting it), so without correction the reinjected frame
// reads as addressed to someone else and the IP stack silently drops it
// before it ever reaches the listening socket. Swapping source and
// destination — the same operation shared_reply already does to address its
// reflected frame back to the real sender — happens to also solve this,
// since the request's own source is this device's own address.
INLINE int local_reply(struct __sk_buff *skb, bool ethernet) {
    const struct sb_fakeip_icmp_control *control = load_control();
    if (control == 0 || (control->flags & SB_FAKEIP_ICMP_FLAG_ENABLED) == 0U) return TC_ACT_UNSPEC;
    if (skb->ingress_ifindex != 0U) return TC_ACT_UNSPEC;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u16 ether_type;
    __u32 l3_offset;
    if (ethernet) {
        if (!parse_ethernet(data, data_end, &ether_type, &l3_offset)) return TC_ACT_UNSPEC;
    } else {
        ether_type = network_order16(skb->protocol);
        l3_offset = 0U;
    }
    if (ether_type == ETH_P_IP_VALUE && (control->flags & SB_FAKEIP_ICMP_FLAG_IPV4) != 0U) {
        struct ipv4_header *ip;
        struct icmp_echo_header *icmp;
        if (!find_ipv4_echo_request(data, data_end, skb->len, l3_offset, control, &ip, &icmp)) return TC_ACT_UNSPEC;
        __be32 old_source = ip->source;
        __be32 old_destination = ip->destination;
        __u8 old_type = icmp->type;
        __u8 old_code = icmp->code;
        if (ethernet && !swap_ethernet_addresses(skb)) { record_fakeip_icmp_stat(SB_FAKEIP_ICMP_STAT_REWRITE_FAILURE); return TC_ACT_SHOT; }
        int result = reply_ipv4_echo(skb, l3_offset, old_source, old_destination, old_type, old_code);
        if (result != TC_ACT_OK) return result;
        return redirect((int)skb->ifindex, BPF_F_INGRESS);
    }
    if (ether_type == ETH_P_IPV6_VALUE && (control->flags & SB_FAKEIP_ICMP_FLAG_LOCAL_IPV6) != 0U) {
        struct ipv6_header *ip;
        struct icmp_echo_header *icmp;
        if (!find_ipv6_echo_request(data, data_end, skb->len, l3_offset, control, &ip, &icmp)) return TC_ACT_UNSPEC;
        __u8 old_addresses[32];
        __builtin_memcpy(old_addresses, ip->source, 16U);
        __builtin_memcpy(old_addresses + 16U, ip->destination, 16U);
        __u8 old_type = icmp->type;
        __u8 old_code = icmp->code;
        if (ethernet && !swap_ethernet_addresses(skb)) { record_fakeip_icmp_stat(SB_FAKEIP_ICMP_STAT_REWRITE_FAILURE); return TC_ACT_SHOT; }
        int result = reply_ipv6_echo(skb, l3_offset, old_addresses, old_type, old_code);
        if (result != TC_ACT_OK) return result;
        return redirect((int)skb->ifindex, BPF_F_INGRESS);
    }
    return TC_ACT_UNSPEC;
}

SEC("classifier/fakeip_icmp_local_reply_ethernet")
int singbox_fakeip_icmp_local_reply_ethernet(struct __sk_buff *skb) {
    return local_reply(skb, true);
}

SEC("classifier/fakeip_icmp_local_reply_raw_ip")
int singbox_fakeip_icmp_local_reply_raw_ip(struct __sk_buff *skb) {
    return local_reply(skb, false);
}

// shared_reply is the mirror image, at TC ingress on a shared interface,
// alongside whichever shared classifier (socket-assign or packet-rewrite) is
// already attached there. A match is bounced back out the same interface
// toward the LAN client that asked, with bpf_redirect(ifindex, 0) — no
// BPF_F_INGRESS, since this reply is genuinely transmitted rather than
// looped back to this box's own receive path. On an Ethernet interface the
// Ethernet source and destination are swapped the same way the IP addresses
// are, so the frame actually reaches the client that sent the request.
INLINE int shared_reply(struct __sk_buff *skb, bool ethernet) {
    const struct sb_fakeip_icmp_control *control = load_control();
    if (control == 0 || (control->flags & SB_FAKEIP_ICMP_FLAG_ENABLED) == 0U) return TC_ACT_UNSPEC;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u16 ether_type;
    __u32 l3_offset;
    if (ethernet) {
        if (!parse_ethernet(data, data_end, &ether_type, &l3_offset)) return TC_ACT_UNSPEC;
    } else {
        ether_type = network_order16(skb->protocol);
        l3_offset = 0U;
    }
    if (ether_type == ETH_P_IP_VALUE && (control->flags & SB_FAKEIP_ICMP_FLAG_IPV4) != 0U) {
        struct ipv4_header *ip;
        struct icmp_echo_header *icmp;
        if (!find_ipv4_echo_request(data, data_end, skb->len, l3_offset, control, &ip, &icmp)) return TC_ACT_UNSPEC;
        __be32 old_source = ip->source;
        __be32 old_destination = ip->destination;
        __u8 old_type = icmp->type;
        __u8 old_code = icmp->code;
        if (ethernet && !swap_ethernet_addresses(skb)) { record_fakeip_icmp_stat(SB_FAKEIP_ICMP_STAT_REWRITE_FAILURE); return TC_ACT_SHOT; }
        int result = reply_ipv4_echo(skb, l3_offset, old_source, old_destination, old_type, old_code);
        if (result != TC_ACT_OK) return result;
        return redirect((int)skb->ifindex, 0U);
    }
    if (ether_type == ETH_P_IPV6_VALUE && (control->flags & SB_FAKEIP_ICMP_FLAG_SHARED_IPV6) != 0U) {
        struct ipv6_header *ip;
        struct icmp_echo_header *icmp;
        if (!find_ipv6_echo_request(data, data_end, skb->len, l3_offset, control, &ip, &icmp)) return TC_ACT_UNSPEC;
        __u8 old_addresses[32];
        __builtin_memcpy(old_addresses, ip->source, 16U);
        __builtin_memcpy(old_addresses + 16U, ip->destination, 16U);
        __u8 old_type = icmp->type;
        __u8 old_code = icmp->code;
        if (ethernet && !swap_ethernet_addresses(skb)) { record_fakeip_icmp_stat(SB_FAKEIP_ICMP_STAT_REWRITE_FAILURE); return TC_ACT_SHOT; }
        int result = reply_ipv6_echo(skb, l3_offset, old_addresses, old_type, old_code);
        if (result != TC_ACT_OK) return result;
        return redirect((int)skb->ifindex, 0U);
    }
    return TC_ACT_UNSPEC;
}

SEC("classifier/fakeip_icmp_shared_reply_ethernet")
int singbox_fakeip_icmp_shared_reply_ethernet(struct __sk_buff *skb) {
    return shared_reply(skb, true);
}

SEC("classifier/fakeip_icmp_shared_reply_raw_ip")
int singbox_fakeip_icmp_shared_reply_raw_ip(struct __sk_buff *skb) {
    return shared_reply(skb, false);
}

char _license[] SEC("license") = "GPL";
