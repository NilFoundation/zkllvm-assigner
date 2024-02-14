
#define BOOST_TEST_MODULE input_signature_parser_test

#include <boost/test/unit_test.hpp>
#include <nil/blueprint/signature_parser.hpp>

using namespace nil::blueprint;

BOOST_AUTO_TEST_SUITE(input_signature_parser_suite)

BOOST_AUTO_TEST_CASE(input_signature_parser_simple) {
    BOOST_TEST(signature_parser().parse("struct"));
    BOOST_TEST(signature_parser().parse("struct<field>"));
    BOOST_TEST(signature_parser().parse("array<int>"));
    BOOST_TEST(signature_parser().parse("struct<int>>") == false);
}

BOOST_AUTO_TEST_SUITE_END()
