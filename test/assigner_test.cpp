#define BOOST_TEST_MODULE assigner_eval_test

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>

#ifndef BOOST_FILESYSTEM_NO_DEPRECATED
#define BOOST_FILESYSTEM_NO_DEPRECATED
#endif
#ifndef BOOST_SYSTEM_NO_DEPRECATED
#define BOOST_SYSTEM_NO_DEPRECATED
#endif

#include <boost/json/src.hpp>
#include <boost/circular_buffer.hpp>
#include <boost/optional.hpp>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/log/trivial.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/ed25519.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <ios>

#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/poseidon.hpp>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/constraint_system.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/assignment_table.hpp>

#include <nil/blueprint/assigner.hpp>
#include <nil/blueprint/asserts.hpp>
#include <nil/blueprint/utils/satisfiability_check.hpp>

#include <llvm/Support/CommandLine.h>
#include <llvm/Support/Signals.h>

#include <variant>
#include <stack>

#include <boost/format.hpp>
#include <boost/log/trivial.hpp>

#include <nil/blueprint/blueprint/plonk/assignment_proxy.hpp>
#include <nil/blueprint/blueprint/plonk/circuit_proxy.hpp>
#include <nil/blueprint/components/hashes/poseidon/plonk/poseidon.hpp>
#include <nil/blueprint/components/hashes/sha2/plonk/sha256.hpp>
#include <nil/blueprint/components/hashes/sha2/plonk/sha512.hpp>

#include <llvm/IRReader/IRReader.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include "llvm/IR/Constants.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/TypeFinder.h"
#include "llvm/IR/TypedPointerType.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"

#include <nil/blueprint/logger.hpp>
#include <nil/blueprint/input_reader.hpp>
#include <nil/blueprint/memory.hpp>
#include <nil/blueprint/non_native_marshalling.hpp>
#include <nil/blueprint/stack.hpp>
#include <nil/blueprint/integers/addition.hpp>
#include <nil/blueprint/integers/subtraction.hpp>
#include <nil/blueprint/integers/multiplication.hpp>
#include <nil/blueprint/integers/division.hpp>
#include <nil/blueprint/integers/division_remainder.hpp>
#include <nil/blueprint/integers/bit_shift.hpp>
#include <nil/blueprint/integers/bit_de_composition.hpp>

#include <nil/blueprint/comparison/comparison.hpp>
#include <nil/blueprint/bitwise/and.hpp>
#include <nil/blueprint/bitwise/or.hpp>
#include <nil/blueprint/bitwise/xor.hpp>

#include <nil/blueprint/boolean/logic_ops.hpp>

#include <nil/blueprint/fields/addition.hpp>
#include <nil/blueprint/fields/subtraction.hpp>
#include <nil/blueprint/fields/multiplication.hpp>
#include <nil/blueprint/fields/division.hpp>

#include <nil/blueprint/curves/addition.hpp>
#include <nil/blueprint/curves/subtraction.hpp>
#include <nil/blueprint/curves/multiplication.hpp>
#include <nil/blueprint/curves/init.hpp>

#include <nil/blueprint/hashes/sha2_256.hpp>
#include <nil/blueprint/hashes/sha2_512.hpp>

#include <nil/blueprint/handle_component.hpp>

#include <nil/blueprint/recursive_prover/fri_lin_inter.hpp>
#include <nil/blueprint/recursive_prover/fri_cosets.hpp>
#include <nil/blueprint/recursive_prover/gate_arg_verifier.hpp>
#include <nil/blueprint/recursive_prover/permutation_arg_verifier.hpp>
#include <nil/blueprint/recursive_prover/lookup_arg_verifier.hpp>
#include <nil/blueprint/recursive_prover/fri_array_swap.hpp>

#include <nil/blueprint/bls_signature/bls12_381_pairing.hpp>
#include <nil/blueprint/bls_signature/fp12_multiplication.hpp>
#include <nil/blueprint/bls_signature/is_in_g1.hpp>
#include <nil/blueprint/bls_signature/is_in_g2.hpp>
#include <nil/blueprint/bls_signature/h2c.hpp>
#include <nil/blueprint/component_mockups/comparison.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/algebra/algorithms/pair.hpp>

using namespace nil;
using namespace nil::crypto3;
using namespace nil::blueprint;

void run_native_pallas(std::string filename,
                       const boost::json::array &public_input,
                       const boost::json::array &private_input,
                       std::vector<unsigned>
                           expected_result) {
    llvm::sys::PrintStackTraceOnErrorSignal("assigner_run_test");

    using Field = typename algebra::curves::pallas::base_field_type;
    auto level = boost::log::trivial::info;
    generation_mode mode = generation_mode::assignments() | generation_mode::circuit();
    zk::snark::plonk_table_description<Field> desc(15, 1, 35, 56);

    assigner<Field> assigner_instance(desc, level, 1, 1, mode, "", no_print, true);

    BOOST_TEST(assigner_instance.parse_ir_file(filename.c_str()));

    BOOST_TEST(assigner_instance.evaluate(public_input, private_input));

    auto return_value = assigner_instance.get_return_value();
    BOOST_TEST(return_value.size() == expected_result.size());

    for (auto i = 0; i < expected_result.size(); ++i) {
        auto expected = Field::integral_type(expected_result[i]);
        BOOST_TEST(return_value[i] == expected);
    }
}

BOOST_AUTO_TEST_SUITE(assigner_eval_suite)

BOOST_AUTO_TEST_CASE(assigner_eval_load_store_i32) {
    auto test_ir_file = std::string(TEST_IR_DIR) + "native_pallas/load_store_i32.ll";
    run_native_pallas(test_ir_file, boost::json::array(), boost::json::array(), {9});
}

BOOST_AUTO_TEST_CASE(assigner_eval_load_store_pallas_base) {
    auto test_ir_file = std::string(TEST_IR_DIR) + "native_pallas/load_store_pallas_base.ll";
    run_native_pallas(test_ir_file, boost::json::array(), boost::json::array(), {9});
}

BOOST_AUTO_TEST_CASE(assigner_eval_load_store_pallas_scalar) {
    auto test_ir_file = std::string(TEST_IR_DIR) + "native_pallas/load_store_pallas_scalar.ll";
    run_native_pallas(test_ir_file, boost::json::array(), boost::json::array(), {9});
}

BOOST_AUTO_TEST_CASE(assigner_eval_getelementptr_1) {
    auto test_ir_file = std::string(TEST_IR_DIR) + "native_pallas/getelementptr_1.ll";
    run_native_pallas(test_ir_file, boost::json::array(), boost::json::array(), {16});
}

BOOST_AUTO_TEST_CASE(assigner_eval_getelementptr_2) {
    auto test_ir_file = std::string(TEST_IR_DIR) + "native_pallas/getelementptr_2.ll";
    run_native_pallas(test_ir_file, boost::json::array(), boost::json::array(), {32});
}

BOOST_AUTO_TEST_CASE(assigner_eval_getelementptr_3) {
    auto test_ir_file = std::string(TEST_IR_DIR) + "native_pallas/getelementptr_3.ll";
    run_native_pallas(test_ir_file, boost::json::array(), boost::json::array(), {8});
}

BOOST_AUTO_TEST_CASE(assigner_eval_getelementptr_4) {
    auto test_ir_file = std::string(TEST_IR_DIR) + "native_pallas/getelementptr_4.ll";
    run_native_pallas(test_ir_file, boost::json::array(), boost::json::array(), {1327});
}

BOOST_AUTO_TEST_SUITE_END()
