#include <bogons/bogons.hpp>
#include <iostream>
#include <string_view>
#include <cassert>

static int g_failures = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        std::cerr << "FAILED: " << (msg) << std::endl; \
        g_failures++; \
    } \
} while (0)

// ---------------------------------------------------------------------------
// Compile-time constexpr validation
// ---------------------------------------------------------------------------
static_assert(bogons::VERSION == "1.4.1");
static_assert(bogons::is_public_asn(15169));
static_assert(!bogons::is_public_asn(0));
static_assert(!bogons::is_public_asn(23456));
static_assert(!bogons::is_public_asn(64512));
static_assert(!bogons::is_public_asn(4200000000U));
static_assert(bogons::is_public_ipv4(0x08080808U)); // 8.8.8.8
static_assert(!bogons::is_public_ipv4(0x0A010203U)); // 10.1.2.3
static_assert(!bogons::is_public_ipv4(0x7F000001U)); // 127.0.0.1
static_assert(bogons::valid_public_prefix_v4(0x08080800U, 24));
static_assert(!bogons::valid_public_prefix_v4(0x08080801U, 24)); // host bits

void test_asn_validation() {
    std::cout << "Testing ASN validation...\n";

    struct TestCase {
        uint32_t asn;
        bool want_public;
        std::string_view rfc;
    };

    TestCase cases[] = {
        { 0, false, "RFC 6483" },
        { 1, true, "" },
        { 15169, true, "" },
        { 23456, false, "RFC 6793" },
        { 64496, false, "RFC 5398" },
        { 64511, false, "RFC 5398" },
        { 64512, false, "RFC 1930" },
        { 65534, false, "RFC 1930" },
        { 65535, false, "RFC 7300" },
        { 65536, false, "RFC 5398" },
        { 65551, false, "RFC 5398" },
        { 65552, false, "RFC 7249" },
        { 131071, false, "RFC 7249" },
        { 131072, true, "" },
        { 4199999999U, true, "" },
        { 4200000000U, false, "RFC 6996" },
        { 4294967294U, false, "RFC 6996" },
        { 4294967295U, false, "RFC 7300" },
    };

    for (const auto& tc : cases) {
        auto res = bogons::check_asn(tc.asn);
        TEST_ASSERT(res.is_public == tc.want_public, "ASN check mismatch for: " + std::to_string(tc.asn));
        if (!tc.want_public) {
            TEST_ASSERT(res.reason.find(tc.rfc) != std::string_view::npos,
                        "ASN reason mismatch: expected " + std::string(tc.rfc) + ", got " + std::string(res.reason));
        }
    }
}

void test_asn_parsing() {
    std::cout << "Testing ASN parsing...\n";

    TEST_ASSERT(bogons::parse_asn("15169") == 15169, "parse 15169");
    TEST_ASSERT(bogons::parse_asn("AS15169") == 15169, "parse AS15169");
    TEST_ASSERT(bogons::parse_asn("as15169") == 15169, "parse as15169");
    TEST_ASSERT(bogons::parse_asn("1.0") == 65536, "parse 1.0 (asdot)");
    TEST_ASSERT(bogons::parse_asn("1.1") == 65537, "parse 1.1 (asdot)");
    TEST_ASSERT(bogons::parse_asn("AS1.0") == 65536, "parse AS1.0");

    TEST_ASSERT(!bogons::parse_asn(""), "parse empty");
    TEST_ASSERT(!bogons::parse_asn("ghost"), "parse ghost");
    TEST_ASSERT(!bogons::parse_asn("1.2.3"), "parse 1.2.3");
}

void test_ip_validation() {
    std::cout << "Testing IP validation...\n";

    struct TestCase {
        std::string_view ip;
        bool want_public;
    };

    TestCase cases[] = {
        // IPv4 Global Unicast
        { "1.1.1.1", true },
        { "8.8.8.8", true },
        { "192.0.1.1", true },
        // IPv4 Bogons
        { "0.0.0.1", false },
        { "127.0.0.1", false },
        { "10.1.2.3", false },
        { "172.16.1.1", false },
        { "172.31.255.255", false },
        { "192.168.1.1", false },
        { "100.64.0.1", false },
        { "169.254.1.1", false },
        { "192.0.0.1", false },
        { "192.0.2.1", false },
        { "198.51.100.1", false },
        { "203.0.113.1", false },
        { "198.18.0.1", false },
        { "198.19.255.255", false },
        { "224.0.0.1", false },
        { "240.0.0.1", false },
        { "255.255.255.255", false },
        { "192.88.99.1", false },
        { "192.31.196.1", false },
        { "192.52.193.1", false },
        { "192.0.0.170", false },
        { "192.0.0.9", false },
        // IPv6 Global Unicast
        { "2600::", true },
        { "2001:4860:4860::8888", true },
        { "3fff::1", true },
        // IPv6 Bogons
        { "::1", false },
        { "::", false },
        { "fe80::1", false },
        { "fc00::1", false },
        { "fd00::1", false },
        { "2001::1", false },
        { "2001:1:2::3", false },
        { "2001:10::1", false },
        { "2001:2::1", false },
        { "2001:db8::1", false },
        { "2002::1", false },
        { "100::1", false },
        { "64:ff9b::1", false },
        { "64:ff9b:1::1", false },
        { "3ffe::1", false },
        { "ff02::1", false },
        { "2620:4f:8000::1", false },
        { "2001:30::1", false },
        { "2001:3::1", false },
        { "4000::1", false },
        // Mapped IPv6
        { "::ffff:1.2.3.4", true },
        { "::ffff:10.0.0.1", false },
    };

    for (const auto& tc : cases) {
        auto res = bogons::check_ip(tc.ip);
        TEST_ASSERT(res.is_public == tc.want_public, "IP mismatch for: " + std::string(tc.ip));
    }

    // Malformed IP strings
    TEST_ASSERT(!bogons::is_public_ip(""), "empty IP");
    TEST_ASSERT(!bogons::is_public_ip("ghost"), "ghost IP");
    TEST_ASSERT(!bogons::is_public_ip("1.1.1.1.1"), "1.1.1.1.1");
    TEST_ASSERT(!bogons::is_public_ip(":::"), ":::");
    TEST_ASSERT(!bogons::is_public_ip("2001:db8::z"), "invalid hex");
}

void test_bgp_prefix_validation() {
    std::cout << "Testing BGP prefix validation...\n";

    // Valid IPv4
    TEST_ASSERT(bogons::valid_public_prefix("8.8.8.0/24"), "valid 8.8.8.0/24");
    TEST_ASSERT(bogons::valid_public_prefix("1.1.1.0/24"), "valid 1.1.1.0/24");
    TEST_ASSERT(bogons::valid_public_prefix("12.0.0.0/8"), "valid 12.0.0.0/8");

    // Invalid IPv4
    TEST_ASSERT(!bogons::valid_public_prefix("8.8.8.8/32"), "too long v4");
    TEST_ASSERT(!bogons::valid_public_prefix("8.0.0.0/7"), "too short v4");
    TEST_ASSERT(!bogons::valid_public_prefix("10.0.0.0/8"), "private v4");
    TEST_ASSERT(!bogons::valid_public_prefix("8.8.8.1/24"), "host bits v4");

    // Valid IPv6
    TEST_ASSERT(bogons::valid_public_prefix("2600::/16"), "valid 2600::/16");
    TEST_ASSERT(bogons::valid_public_prefix("2001:4860::/32"), "valid 2001:4860::/32");
    TEST_ASSERT(bogons::valid_public_prefix("2a0d:1a40::/32"), "valid 2a0d:1a40::/32");
    TEST_ASSERT(bogons::valid_public_prefix("2001:4860:4860::/48"), "valid /48 v6");

    // Invalid IPv6
    TEST_ASSERT(!bogons::valid_public_prefix("2600::/15"), "too short v6");
    TEST_ASSERT(!bogons::valid_public_prefix("2600::/64"), "too long v6");
    TEST_ASSERT(!bogons::valid_public_prefix("2001:db8::/32"), "doc v6");
    TEST_ASSERT(!bogons::valid_public_prefix("2001:4860::1/32"), "host bits v6");
}

int main() {
    test_asn_validation();
    test_asn_parsing();
    test_ip_validation();
    test_bgp_prefix_validation();

    if (g_failures == 0) {
        std::cout << "ALL TESTS PASSED!\n";
        return 0;
    } else {
        std::cerr << g_failures << " TESTS FAILED!\n";
        return 1;
    }
}
