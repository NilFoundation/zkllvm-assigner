#define BOOST_TEST_MODULE memory_segment_test

#include <boost/test/unit_test.hpp>
#include <nil/blueprint/mem/segment.hpp>

using namespace nil::blueprint::mem;

BOOST_AUTO_TEST_SUITE(memory_segment_suite)

BOOST_AUTO_TEST_CASE(memory_segment_equality) {
    segment a(0, 4);
    segment b;
    b.pointer = 0;
    b.size = 4;
    segment c(0, 8);
    BOOST_TEST(a == b);
    BOOST_TEST(a != c);
}

BOOST_AUTO_TEST_CASE(memory_segment_comparison) {
    segment a(0, 4);
    segment b(4, 4);
    segment c(0, 8);
    BOOST_TEST(a < b);
    BOOST_TEST(b > a);
    BOOST_TEST(!(a < c));
}

BOOST_AUTO_TEST_CASE(memory_segment_contains) {
    segment a(0, 4);
    BOOST_TEST(a.contains(0));
    BOOST_TEST(a.contains(1));
    BOOST_TEST(!a.contains(4));
}

BOOST_AUTO_TEST_CASE(memory_segment_contains_segment) {
    segment a(0, 4);
    segment b(1, 2);
    segment c(0, 5);
    BOOST_TEST(a.contains(b));
    BOOST_TEST(!a.contains(c));
}

BOOST_AUTO_TEST_CASE(memory_segment_intersects) {
    segment a(0, 4);
    segment b(0, 16);
    segment c(4, 4);
    BOOST_TEST(a.intersects(b));
    BOOST_TEST(!a.intersects(c));
    BOOST_TEST(b.intersects(c));
}

BOOST_AUTO_TEST_CASE(memory_segment_print_string) {
    segment a(0xffffffff00000000, 0xaaaaaaaa);
    segment b(0x1, 0x1);
    BOOST_TEST(a.print_string() == std::string("0xffffffff00000000+aaaaaaaa"));
    BOOST_TEST(b.print_string() == std::string("0x0000000000000001+00000001"));
}

BOOST_AUTO_TEST_SUITE_END()
