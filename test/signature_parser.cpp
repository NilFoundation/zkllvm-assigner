
#define BOOST_TEST_MODULE input_signature_parser_test

#include <boost/test/unit_test.hpp>
#include <nil/blueprint/signature_parser.hpp>

using namespace nil::blueprint;

BOOST_AUTO_TEST_SUITE(input_signature_parser_suite)

BOOST_AUTO_TEST_CASE(input_signature_parser_simple) {
    BOOST_TEST(signature_parser().parse("struct"));
    BOOST_TEST(signature_parser().parse("struct<field>"));
    BOOST_TEST(signature_parser().parse("array<int>"));
    BOOST_TEST(signature_parser().parse("field"));
    BOOST_TEST(signature_parser().parse("field<pallas_base>"));
    BOOST_TEST(signature_parser().parse("curve<pallas>"));
    BOOST_TEST(signature_parser().parse("int"));
    BOOST_TEST(signature_parser().parse("array<int>"));
    BOOST_TEST(signature_parser().parse("array<field>"));
    BOOST_TEST(signature_parser().parse("array<field<pallas_base>>"));
    BOOST_TEST(signature_parser().parse("struct<int>"));
    BOOST_TEST(signature_parser().parse("struct<int, field<pallas_base>>"));
    BOOST_TEST(signature_parser().parse("array<struct<field<pallas_base>>>"));
    BOOST_TEST(signature_parser().parse("struct"
          "<"
                  "vector<int>,"
                  "array"
                  "<"
                        "struct<field<ed25519_scalar>, string>"
                  ">"
          ">"));

    BOOST_TEST(signature_parser().parse("struct<int>>") == false);
    BOOST_TEST(signature_parser().parse("array") == false);
    BOOST_TEST(signature_parser().parse("vector") == false);
    BOOST_TEST(signature_parser().parse("field<pa") == false);
    BOOST_TEST(signature_parser().parse("xyz42") == false);
    BOOST_TEST(signature_parser().parse("") == false);
}

BOOST_AUTO_TEST_SUITE_END()
