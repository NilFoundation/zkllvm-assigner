#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <map>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/constraint_system.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/assignment_table.hpp>

#include <nil/blueprint/assigner.hpp>

#define BOOST_TEST_MODULE input_reader_test

#include <boost/test/unit_test.hpp>
#include <nil/blueprint/signature_parser.hpp>

using namespace nil::blueprint;
using BlueprintFieldType = typename nil::crypto3::algebra::curves::pallas::base_field_type;
using var = nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

llvm::DataLayout dl("");
LayoutResolver layout_resolver(dl);
program_memory<var> memory(100);
stack_frame<var> frame;
std::nullptr_t empty_assignmnt;
boost::json::array empty_private_input;
InputReader<BlueprintFieldType, var, std::nullptr_t> input_reader(frame, memory, empty_assignmnt, layout_resolver);
logger test_logger;

boost::json::array read_json_string(std::string json_string) {
    std::stringstream stream;
    stream << json_string;

    boost::json::stream_parser p;
    boost::json::error_code ec;
    while (!stream.eof()) {
        char input_string[256];
        stream.read(input_string, sizeof(input_string) - 1);
        input_string[stream.gcount()] = '\0';
        p.write(input_string, ec);
        ASSERT(!ec);
    }
    p.finish(ec);
    ASSERT(!ec);
    boost::json::value parsed_value = p.release();
    ASSERT(parsed_value.is_array());
    return parsed_value.as_array();
}

llvm::Function *get_func_by_name(llvm::Module *module, const char *name) {
    auto entry_point_it = module->end();
    for (auto function_it = module->begin(); function_it != module->end(); ++function_it) {
        if (function_it->getName() == name) {
            entry_point_it = function_it;
        }
    }
    if (entry_point_it == module->end()) {
        return nullptr;
    }
    return &*entry_point_it;
}

bool check_vector_equality(const std::vector<typename BlueprintFieldType::value_type> &actual,
                           const std::vector<typename BlueprintFieldType::value_type> &expected) {
    if (actual.size() != expected.size()) {
        return false;
    }
    for (size_t i = 0; i < actual.size(); ++i) {
        if (actual[i] != expected[i]) {
            return false;
        }
    }
    return true;
}

struct LLVMDataFixture {
    LLVMDataFixture() {
        module = llvm::parseIRFile(IR_FILE, diagnostic, context);
        BOOST_TEST_REQUIRE(module.get() != nullptr);
        arrays_func = get_func_by_name(module.get(), "arrays");
        BOOST_TEST_REQUIRE(arrays_func != nullptr);
        fields_curves_func = get_func_by_name(module.get(), "fields_curves");
        BOOST_TEST_REQUIRE(fields_curves_func != nullptr);
    }

    void test_correct_input(llvm::Function *func,
                            const char *input_string,
                            const std::vector<typename BlueprintFieldType::value_type> expected_result) {
        auto input_array = read_json_string(input_string);
        BOOST_TEST_REQUIRE(input_reader.fill_public_input(*func, input_array, empty_private_input, test_logger));
        BOOST_TEST(check_vector_equality(input_reader.get_public_input(), expected_result));
        input_reader.reset();
    }

    void test_error_message(llvm::Function *func, const char *input_string, const char *error_message) {
        auto input_array = read_json_string(input_string);
        BOOST_TEST(input_reader.fill_public_input(*func, input_array, empty_private_input, test_logger) == false);
        BOOST_TEST(input_reader.get_error() == error_message);
        input_reader.reset();
    }

    llvm::LLVMContext context;
    llvm::SMDiagnostic diagnostic;
    std::unique_ptr<llvm::Module> module;
    llvm::Function *arrays_func;
    llvm::Function *fields_curves_func;
};

BOOST_FIXTURE_TEST_SUITE(input_reader_suite, LLVMDataFixture)

BOOST_AUTO_TEST_CASE(input_reader_actual_format) {

    std::vector<typename BlueprintFieldType::value_type> expected = {1, 2, 3, 4, 5, 6, 7, 8};
    const char *input_string = R"([ {"array<field<pallas_base>>": [1,2, 3 ]},
                                               {"array<field<pallas_base>>": [ 4, 5, 6, 7, 8]}])";

    test_correct_input(arrays_func, input_string, expected);
}

BOOST_AUTO_TEST_CASE(input_reader_legacy_format) {

    std::vector<typename BlueprintFieldType::value_type> expected = {1, 2, 3, 4, 5, 6, 7, 8};
    const char *input_string = R"([ {"array": [{"field":1}, {"field": 2}, {"field" :3} ]},
                                               {"array": [ {"field":4}, {"field":5}, {"field":6}, {"field":7}, {"field":8}]}])";
    test_correct_input(arrays_func, input_string, expected);
}

BOOST_AUTO_TEST_CASE(input_reader_mixed_format) {

    std::vector<typename BlueprintFieldType::value_type> expected = {0x12345678901234567890_cppui255, 2, 3, 4, 5, 6, 7, 8};
    const char *input_string = R"([ {"array": [{"field":"0x12345678901234567890"}, {"field": 2}, {"field<pallas_base>" :3} ]},
                                               {"array<field<pallas_base>>": [ 4, 5, 6, 7, 8]}])";
    test_correct_input(arrays_func, input_string, expected);
}

BOOST_AUTO_TEST_CASE(input_reader_undefined_type) {

    const char *input_string = R"([ {"array": [{"field":1}, 2, {"field<pallas_base>" :3} ]},
                                               {"array<field>": [ 4, 5, 6, 7, 8]}])";
    const char *expected_error = R"(Expected object with a signature as an array elem, got "2")";
    test_error_message(arrays_func, input_string, expected_error);
}

BOOST_AUTO_TEST_CASE(input_reader_type_defined_twice) {

    const char *input_string = R"([ {"array<field>": [{"field":1}, {"field": 2}, {"field" :3} ]},
                                               {"array<field>": [ 4, 5, 6, 7, 8]}])";
    const char *expected_error = R"(Expected int or string as a field value, got "{"field":1}")";
    test_error_message(arrays_func, input_string, expected_error);
}

BOOST_AUTO_TEST_CASE(input_reader_wrong_num_elements) {

    const char *input_string = R"([ {"array<field>": [1, 2, 3 ]},
                                               {"array<field>": [ 4, 5, 6, 7, 8, 9]}])";
    const char *expected_error = R"(Expected an array with 5 arguments, got "[4,5,6,7,8,9]")";
    test_error_message(arrays_func, input_string, expected_error);
}

BOOST_AUTO_TEST_CASE(input_reader_fields_curves) {

    std::vector<typename BlueprintFieldType::value_type> expected = {1, 2, 0, 0, 0, 4, 5, 6, 0, 0, 0, 7, 0, 0, 0};
    const char *input_string = R"([ {"field<pallas_base>": 1},
                                    {"field<ed25519_base>" : 2},
                                    {"curve<pallas>": [4, 5]},
                                    {"curve<ed25519>": [6, 7]}
                                  ])";
    test_correct_input(fields_curves_func, input_string, expected);
}

BOOST_AUTO_TEST_CASE(input_reader_fields_wrong_field_type) {

    const char *input_string_wrong_field = R"([ {"field<bls12381_base>": 1},
                                    {"field<ed25519_base>" : 2},
                                    {"curve<pallas>": [4, 5]},
                                    {"curve<ed25519>": [6, 7]}
                                    ])";
    const char *expected_error = R"(Wrong kind of field "bls12381_base", expected "pallas_base")";
    test_error_message(fields_curves_func, input_string_wrong_field, expected_error);
}

BOOST_AUTO_TEST_CASE(input_reader_fields_wrong_curve_type) {

    const char *input_string_wrong_curve = R"([ {"field<pallas_base>": 1},
                                    {"field<ed25519_base>" : 2},
                                    {"curve<ed25519>": [4, 5]},
                                    {"curve<ed25519>": [6, 7]}
                                    ])";
    const char *expected_error = R"(Wrong kind of curve "ed25519", expected "pallas")";
    test_error_message(fields_curves_func, input_string_wrong_curve, expected_error);
}

BOOST_AUTO_TEST_CASE(input_reader_fields_wrong_amount) {

    const char *input_string_wrong_amount = R"([ {"field<pallas_base>": 1},
                                    {"field<ed25519_base>" : 2},
                                    {"curve<pallas>": [4, 5]},
                                    {"curve<ed25519>": [6, 7]},
                                    {"curve<bls12381>": [5, 5]}
                                    ])";
    const char *expected_error = R"(Too many values in the input files, public + private input sizes must be equal to passed argument size)";
    test_error_message(fields_curves_func, input_string_wrong_amount, expected_error);
}

BOOST_AUTO_TEST_SUITE_END()
