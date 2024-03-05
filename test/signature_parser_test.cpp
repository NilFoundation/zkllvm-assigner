
#define BOOST_TEST_MODULE input_signature_parser_test

#include <boost/test/unit_test.hpp>
#include <nil/blueprint/signature_parser.hpp>

using namespace nil::blueprint;

BOOST_AUTO_TEST_SUITE(input_signature_parser_suite)

BOOST_AUTO_TEST_CASE(input_signature_parser_simple) {
    BOOST_TEST(signature_parser().parse("struct"));
    BOOST_TEST(signature_parser().parse("struct<field>"));
    BOOST_TEST(signature_parser().parse("array<int>"));
    BOOST_TEST(signature_parser().parse("array"));
    BOOST_TEST(signature_parser().parse("vector"));
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
    BOOST_TEST(signature_parser().parse("field<pa") == false);
    BOOST_TEST(signature_parser().parse("xyz42") == false);
    BOOST_TEST(signature_parser().parse("") == false);
}

BOOST_AUTO_TEST_CASE(input_signature_parser_check_tree) {
    signature_parser sp;
    BOOST_TEST(sp.parse("array<field<pallas_base>>"));
    const signature_node &array_node = sp.get_tree();
    BOOST_TEST(array_node.children.size() == 1);
    BOOST_TEST(array_node.elem == json_elem::ARRAY);
    const signature_node &field_node = array_node.children[0];
    BOOST_TEST(field_node.children.size() == 1);
    BOOST_TEST(field_node.elem == json_elem::FIELD);
    const signature_node &field_kind_node = field_node.children[0];
    BOOST_TEST(field_kind_node.children.size() == 0);
    BOOST_TEST(field_kind_node.elem == json_elem::PALLAS_BASE);
}

BOOST_AUTO_TEST_SUITE_END()
