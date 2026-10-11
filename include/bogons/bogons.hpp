/*
 * Copyright (C) 2026 Darren O'Connor <mellow.drifter@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef BOGONS_BOGONS_HPP
#define BOGONS_BOGONS_HPP

#include <array>
#include <cstdint>
#include <string_view>
#include <optional>
#include <charconv>
#include <cstring>
#include <arpa/inet.h>

namespace bogons {

inline constexpr std::string_view VERSION = "1.4.1";

struct Result {
    bool is_public{true};
    std::string_view reason{};

    constexpr explicit operator bool() const noexcept {
        return is_public;
    }
};

// ---------------------------------------------------------------------------
// Internal Rules Definition
// ---------------------------------------------------------------------------

namespace detail {

struct V4Rule {
    uint32_t net;
    uint32_t mask;
    std::string_view reason;
};

struct V6Rule {
    std::array<uint8_t, 16> net;
    uint8_t mask_bits;
    std::string_view reason;
};

struct AsRule {
    uint32_t start;
    uint32_t end;
    std::string_view reason;
};

constexpr uint32_t v4_calc_mask(uint8_t bits) noexcept {
    if (bits == 0) return 0;
    if (bits >= 32) return 0xFFFFFFFFU;
    return ~((1U << (32 - bits)) - 1U);
}

inline constexpr std::array<V4Rule, 23> V4_RULES = {{
    { 0x00000000U, 0xFF000000U, "RFC 1122 (This Host on This Network)" },
    { 0x0A000000U, 0xFF000000U, "RFC 1918 (Private-Use)" },
    { 0x64400000U, 0xFFC00000U, "RFC 6598 (Shared Address Space / CGNAT)" },
    { 0x7F000000U, 0xFF000000U, "RFC 1122 (Loopback)" },
    { 0xA9FE0000U, 0xFFFF0000U, "RFC 3927 (Link-Local)" },
    { 0xAC100000U, 0xFFF00000U, "RFC 1918 (Private-Use)" },
    { 0xC00000AAU, 0xFFFFFFFEU, "RFC 8880 (NAT64/DNS64 Discovery)" },
    { 0xC000000AU, 0xFFFFFFFFU, "RFC 8155 (TURN Anycast)" },
    { 0xC0000009U, 0xFFFFFFFFU, "RFC 7725 (PCP Anycast)" },
    { 0xC0000008U, 0xFFFFFFFFU, "RFC 7600 (IPv4 Dummy Address)" },
    { 0xC0000000U, 0xFFFFFFF8U, "RFC 6333 / RFC 7335 (DS-Lite / Dual-Stack Continuity)" },
    { 0xC0000000U, 0xFFFFFF00U, "RFC 6890 (IETF Protocol Assignments)" },
    { 0xC0000200U, 0xFFFFFF00U, "RFC 5737 (Documentation TEST-NET-1)" },
    { 0xC01FC400U, 0xFFFFFF00U, "RFC 7535 (AS112-v4)" },
    { 0xC034C100U, 0xFFFFFF00U, "RFC 7450 (Automatic Multicast Tunneling - AMT)" },
    { 0xC0586300U, 0xFFFFFF00U, "RFC 7526 (6to4 Relay Anycast - Deprecated)" },
    { 0xC0A80000U, 0xFFFF0000U, "RFC 1918 (Private-Use)" },
    { 0xC6120000U, 0xFFFE0000U, "RFC 2544 (Benchmarking)" },
    { 0xC6336400U, 0xFFFFFF00U, "RFC 5737 (Documentation TEST-NET-2)" },
    { 0xCB007100U, 0xFFFFFF00U, "RFC 5737 (Documentation TEST-NET-3)" },
    { 0xE0000000U, 0xF0000000U, "RFC 1112 (Multicast)" },
    { 0xFFFFFFFFU, 0xFFFFFFFFU, "RFC 919 / RFC 8190 (Limited Broadcast)" },
    { 0xF0000000U, 0xF0000000U, "RFC 1112 (Reserved / Former Class E)" },
}};

inline constexpr std::array<V6Rule, 17> V6_RULES = {{
    // 2001:db8::/32
    { {{ 0x20, 0x01, 0x0d, 0xb8 }}, 32, "RFC 3849 (Documentation)" },
    // 2001::/32
    { {{ 0x20, 0x01, 0x00, 0x00 }}, 32, "RFC 4380 (Teredo)" },
    // 2001:1::1/128
    { {{ 0x20, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 }}, 128, "RFC 7723 (PCP Anycast)" },
    // 2001:1::2/128
    { {{ 0x20, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02 }}, 128, "RFC 8155 (TURN Anycast)" },
    // 2001:2::/48
    { {{ 0x20, 0x01, 0x00, 0x02 }}, 48, "RFC 5180 / RFC 9006 (Benchmarking)" },
    // 2001:3::/32
    { {{ 0x20, 0x01, 0x00, 0x03 }}, 32, "RFC 7450 (Automatic Multicast Tunneling - AMT)" },
    // 2001:4:112::/48
    { {{ 0x20, 0x01, 0x00, 0x04, 0x01, 0x12 }}, 48, "RFC 7535 (AS112-v6)" },
    // 2001:10::/28
    { {{ 0x20, 0x01, 0x00, 0x10 }}, 28, "RFC 4843 (Deprecated ORCHID)" },
    // 2001:20::/28
    { {{ 0x20, 0x01, 0x00, 0x20 }}, 28, "RFC 7343 (ORCHIDv2)" },
    // 2001:30::/28
    { {{ 0x20, 0x01, 0x00, 0x30 }}, 28, "RFC 9385 (Drone Remote ID)" },
    // 2001::/23
    { {{ 0x20, 0x01, 0x00, 0x00 }}, 23, "RFC 2928 (IETF Protocol Assignments)" },
    // 2002::/16
    { {{ 0x20, 0x02 }}, 16, "RFC 3056 / RFC 7526 (6to4 - Deprecated)" },
    // 2620:4f:8000::/48
    { {{ 0x26, 0x20, 0x00, 0x4f, 0x80, 0x00 }}, 48, "RFC 7534 (Direct Delegation AS112)" },
    // 64:ff9b:1::/48
    { {{ 0x00, 0x64, 0xff, 0x9b, 0x00, 0x01 }}, 48, "RFC 8215 (Local-Use IPv4/IPv6 Translation)" },
    // 64:ff9b::/96
    { {{ 0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0 }}, 96, "RFC 6052 (IPv4/IPv6 Translation)" },
    // 100::/64
    { {{ 0x01, 0x00, 0, 0, 0, 0, 0, 0 }}, 64, "RFC 6666 (Discard-Only)" },
    // 3ffe::/16
    { {{ 0x3f, 0xfe }}, 16, "RFC 3701 (6bone - Deprecated / Returned)" },
}};

inline constexpr std::array<AsRule, 9> AS_RULES = {{
    { 0U, 0U, "RFC 6483 / RFC 7607 (Reserved ASN 0)" },
    { 23456U, 23456U, "RFC 6793 (AS_TRANS 4-Byte Transition)" },
    { 64496U, 64511U, "RFC 5398 (Documentation 16-bit)" },
    { 64512U, 65534U, "RFC 1930 / RFC 6996 (Private-Use 16-bit)" },
    { 65535U, 65535U, "RFC 7300 (Reserved 16-bit Last ASN)" },
    { 65536U, 65551U, "RFC 5398 (Documentation 32-bit)" },
    { 65552U, 131071U, "RFC 7249 / IANA (Reserved 32-bit)" },
    { 4200000000U, 4294967294U, "RFC 6996 (Private-Use 32-bit)" },
    { 4294967295U, 4294967295U, "RFC 7300 (Reserved 32-bit Last ASN)" },
}};

constexpr bool v6_match_prefix(const std::array<uint8_t, 16>& octets,
                              const std::array<uint8_t, 16>& net,
                              uint8_t bits) noexcept {
    uint8_t full_bytes = bits / 8;
    for (uint8_t i = 0; i < full_bytes; ++i) {
        if (octets[i] != net[i]) return false;
    }
    uint8_t rem_bits = bits % 8;
    if (rem_bits > 0) {
        uint8_t mask = static_cast<uint8_t>(~((1U << (8 - rem_bits)) - 1U));
        if ((octets[full_bytes] & mask) != (net[full_bytes] & mask)) return false;
    }
    return true;
}

constexpr std::string_view trim_sv(std::string_view sv) noexcept {
    while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t' || sv.front() == '\r' || sv.front() == '\n')) {
        sv.remove_prefix(1);
    }
    while (!sv.empty() && (sv.back() == ' ' || sv.back() == '\t' || sv.back() == '\r' || sv.back() == '\n')) {
        sv.remove_suffix(1);
    }
    return sv;
}

} // namespace detail

// ---------------------------------------------------------------------------
// ASN Checking & Parsing
// ---------------------------------------------------------------------------

constexpr Result check_asn(uint32_t asn) noexcept {
    for (const auto& rule : detail::AS_RULES) {
        if (asn >= rule.start && asn <= rule.end) {
            return {false, rule.reason};
        }
    }
    return {true, {}};
}

constexpr bool is_public_asn(uint32_t asn) noexcept {
    return check_asn(asn).is_public;
}

inline std::optional<uint32_t> parse_asn(std::string_view str) noexcept {
    str = detail::trim_sv(str);
    if (str.empty()) return std::nullopt;

    if (str.size() >= 2 && (str[0] == 'A' || str[0] == 'a') && (str[1] == 'S' || str[1] == 's')) {
        str.remove_prefix(2);
    }
    if (str.empty()) return std::nullopt;

    auto dot_pos = str.find('.');
    if (dot_pos != std::string_view::npos) {
        auto high_sv = str.substr(0, dot_pos);
        auto low_sv = str.substr(dot_pos + 1);
        if (high_sv.empty() || low_sv.empty()) return std::nullopt;

        uint16_t high = 0;
        uint16_t low = 0;
        auto res1 = std::from_chars(high_sv.data(), high_sv.data() + high_sv.size(), high);
        if (res1.ec != std::errc{} || res1.ptr != high_sv.data() + high_sv.size()) return std::nullopt;

        auto res2 = std::from_chars(low_sv.data(), low_sv.data() + low_sv.size(), low);
        if (res2.ec != std::errc{} || res2.ptr != low_sv.data() + low_sv.size()) return std::nullopt;

        return (static_cast<uint32_t>(high) << 16) | static_cast<uint32_t>(low);
    }

    uint32_t val = 0;
    auto res = std::from_chars(str.data(), str.data() + str.size(), val);
    if (res.ec != std::errc{} || res.ptr != str.data() + str.size()) {
        return std::nullopt;
    }
    return val;
}

inline Result check_asn(std::string_view str) noexcept {
    auto opt = parse_asn(str);
    if (!opt) {
        return {false, "Invalid ASN syntax"};
    }
    return check_asn(*opt);
}

inline bool is_public_asn(std::string_view str) noexcept {
    return check_asn(str).is_public;
}

// ---------------------------------------------------------------------------
// IP Validation
// ---------------------------------------------------------------------------

constexpr Result check_ipv4(uint32_t ip) noexcept {
    for (const auto& rule : detail::V4_RULES) {
        if ((ip & rule.mask) == rule.net) {
            return {false, rule.reason};
        }
    }
    return {true, {}};
}

constexpr bool is_public_ipv4(uint32_t ip) noexcept {
    return check_ipv4(ip).is_public;
}

constexpr Result check_ipv6(const std::array<uint8_t, 16>& octets) noexcept {
    // Check for IPv4-mapped IPv6 (::ffff:0:0/96)
    if (octets[0] == 0 && octets[1] == 0 && octets[2] == 0 && octets[3] == 0 &&
        octets[4] == 0 && octets[5] == 0 && octets[6] == 0 && octets[7] == 0 &&
        octets[8] == 0 && octets[9] == 0 && octets[10] == 0xFF && octets[11] == 0xFF) {
        uint32_t v4 = (static_cast<uint32_t>(octets[12]) << 24) |
                      (static_cast<uint32_t>(octets[13]) << 16) |
                      (static_cast<uint32_t>(octets[14]) << 8)  |
                       static_cast<uint32_t>(octets[15]);
        return check_ipv4(v4);
    }

    // Explicit V6 rules
    for (const auto& rule : detail::V6_RULES) {
        if (detail::v6_match_prefix(octets, rule.net, rule.mask_bits)) {
            return {false, rule.reason};
        }
    }

    // ::1 Loopback
    if (octets[0] == 0 && octets[1] == 0 && octets[2] == 0 && octets[3] == 0 &&
        octets[4] == 0 && octets[5] == 0 && octets[6] == 0 && octets[7] == 0 &&
        octets[8] == 0 && octets[9] == 0 && octets[10] == 0 && octets[11] == 0 &&
        octets[12] == 0 && octets[13] == 0 && octets[14] == 0 && octets[15] == 1) {
        return {false, "RFC 4291 (Loopback)"};
    }

    // :: Unspecified
    bool all_zero = true;
    for (uint8_t b : octets) {
        if (b != 0) { all_zero = false; break; }
    }
    if (all_zero) {
        return {false, "RFC 4291 (Unspecified)"};
    }

    // fe80::/10 Link-Local
    if (octets[0] == 0xFE && (octets[1] & 0xC0) == 0x80) {
        return {false, "RFC 4291 (Link-Local)"};
    }

    // fc00::/7 ULA
    if ((octets[0] & 0xFE) == 0xFC) {
        return {false, "RFC 4193 (Unique Local Address / ULA)"};
    }

    // ff00::/8 Multicast
    if (octets[0] == 0xFF) {
        return {false, "RFC 4291 (Multicast)"};
    }

    // Only 2000::/3 is globally routable
    if (octets[0] < 0x20 || octets[0] > 0x3F) {
        return {false, "RFC 4291 (IANA Unallocated / Outside 2000::/3 Global Unicast)"};
    }

    return {true, {}};
}

constexpr bool is_public_ipv6(const std::array<uint8_t, 16>& octets) noexcept {
    return check_ipv6(octets).is_public;
}

inline Result check_ip(std::string_view str) noexcept {
    str = detail::trim_sv(str);
    if (str.empty() || str.size() > 127) {
        return {false, "Invalid IP address syntax"};
    }

    char buf[128];
    std::memcpy(buf, str.data(), str.size());
    buf[str.size()] = '\0';

    struct in_addr in4;
    if (inet_pton(AF_INET, buf, &in4) == 1) {
        return check_ipv4(ntohl(in4.s_addr));
    }

    struct in6_addr in6;
    if (inet_pton(AF_INET6, buf, &in6) == 1) {
        std::array<uint8_t, 16> arr;
        std::memcpy(arr.data(), in6.s6_addr, 16);
        return check_ipv6(arr);
    }

    return {false, "Invalid IP address syntax"};
}

inline bool is_public_ip(std::string_view str) noexcept {
    return check_ip(str).is_public;
}

// ---------------------------------------------------------------------------
// BGP Announcement Validation
// ---------------------------------------------------------------------------

constexpr bool valid_public_prefix_v4(uint32_t ip, uint8_t prefix_len) noexcept {
    if (prefix_len < 8 || prefix_len > 24) return false;
    uint32_t mask = detail::v4_calc_mask(prefix_len);
    if ((ip & mask) != ip) {
        return false;
    }
    return is_public_ipv4(ip);
}

constexpr bool valid_public_prefix_v6(const std::array<uint8_t, 16>& octets, uint8_t prefix_len) noexcept {
    // Check IPv4-mapped
    if (octets[0] == 0 && octets[1] == 0 && octets[2] == 0 && octets[3] == 0 &&
        octets[4] == 0 && octets[5] == 0 && octets[6] == 0 && octets[7] == 0 &&
        octets[8] == 0 && octets[9] == 0 && octets[10] == 0xFF && octets[11] == 0xFF) {
        uint32_t v4 = (static_cast<uint32_t>(octets[12]) << 24) |
                      (static_cast<uint32_t>(octets[13]) << 16) |
                      (static_cast<uint32_t>(octets[14]) << 8)  |
                       static_cast<uint32_t>(octets[15]);
        uint8_t v4_len = prefix_len >= 96 ? prefix_len - 96 : prefix_len;
        return valid_public_prefix_v4(v4, v4_len);
    }

    if (prefix_len < 16 || prefix_len > 48) return false;

    uint8_t full_bytes = prefix_len / 8;
    uint8_t rem_bits = prefix_len % 8;

    if (rem_bits > 0) {
        uint8_t host_mask = static_cast<uint8_t>((1U << (8 - rem_bits)) - 1U);
        if ((octets[full_bytes] & host_mask) != 0) return false;
        full_bytes++;
    }
    for (size_t i = full_bytes; i < 16; ++i) {
        if (octets[i] != 0) return false;
    }

    return is_public_ipv6(octets);
}

inline bool valid_public_prefix(std::string_view cidr) noexcept {
    cidr = detail::trim_sv(cidr);
    auto slash = cidr.find('/');
    if (slash == std::string_view::npos) return false;

    auto ip_sv = cidr.substr(0, slash);
    auto len_sv = cidr.substr(slash + 1);
    if (ip_sv.empty() || len_sv.empty() || ip_sv.size() > 127) return false;

    uint8_t len = 0;
    auto res = std::from_chars(len_sv.data(), len_sv.data() + len_sv.size(), len);
    if (res.ec != std::errc{} || res.ptr != len_sv.data() + len_sv.size()) return false;

    char buf[128];
    std::memcpy(buf, ip_sv.data(), ip_sv.size());
    buf[ip_sv.size()] = '\0';

    struct in_addr in4;
    if (inet_pton(AF_INET, buf, &in4) == 1) {
        return valid_public_prefix_v4(ntohl(in4.s_addr), len);
    }

    struct in6_addr in6;
    if (inet_pton(AF_INET6, buf, &in6) == 1) {
        std::array<uint8_t, 16> arr;
        std::memcpy(arr.data(), in6.s6_addr, 16);
        return valid_public_prefix_v6(arr, len);
    }

    return false;
}

} // namespace bogons

#endif // BOGONS_BOGONS_HPP
