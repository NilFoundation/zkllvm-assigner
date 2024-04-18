//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_TABLE_PIECE_HPP_
#define ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_TABLE_PIECE_HPP_

#include <variant>
#include <stack>

#include <boost/format.hpp>
#include <boost/log/trivial.hpp>

#include <nil/blueprint/blueprint/plonk/assignment_proxy.hpp>
#include <nil/blueprint/blueprint/plonk/circuit_proxy.hpp>
#include <nil/blueprint/components/hashes/poseidon/plonk/poseidon.hpp>
// #include <nil/blueprint/components/hashes/sha2/plonk/sha256.hpp>
// #include <nil/blueprint/components/hashes/sha2/plonk/sha512.hpp>


#include <nil/blueprint/logger.hpp>
#include <nil/blueprint/layout_resolver.hpp>
#include <nil/blueprint/input_reader.hpp>
#include <nil/blueprint/memory.hpp>
#include <nil/blueprint/non_native_marshalling.hpp>
#include <nil/blueprint/stack.hpp>

#include <nil/blueprint/handle_component.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/algebra/algorithms/pair.hpp>
#include <thread>

namespace nil {
    namespace blueprint {


template<typename var>
struct table_piece {
    std::size_t counter;
    std::vector<std::size_t> parent_pieces;
    std::string component_name;
    std::size_t start_row;
    std::vector<var> inputs;
    std::vector<var> outputs;
    bool done;

    table_piece(
        std::size_t c,
        std::vector<std::size_t> pp,
        std::string cn,
        std::size_t sr,
        std::vector<var> in,
        std::vector<var> out
    ) {
        counter = c;
        parent_pieces = pp;
        component_name = cn;
        start_row = sr;
        inputs = in;
        outputs = out;
        done = false;
    };

    boost::json::value to_json() const {
        boost::json::array inputs_json;
        for (const auto& input : inputs) {
            inputs_json.push_back(input.to_json());
        }

        boost::json::array outputs_json;
        for (const auto& output : outputs) {
            outputs_json.push_back(output.to_json());
        }

        boost::json::array parent_pieces_json;
        for (const auto& parent : parent_pieces) {
            parent_pieces_json.push_back(parent);
        }

        return boost::json::object{
            {"counter", counter},
            {"parent_pieces", parent_pieces_json},
            {"component_name", component_name},
            {"start_row", start_row},
            {"inputs", inputs_json},
            {"outputs", outputs_json}
        };
    }

    table_piece(const boost::json::object& obj) {
        counter = obj.at("counter").as_int64();
        for (const auto& item : obj.at("parent_pieces").as_array()) {
            parent_pieces.push_back(item.as_int64());
        }
        component_name = obj.at("component_name").as_string().c_str();
        start_row = obj.at("start_row").as_int64();
        for (const auto& input : obj.at("inputs").as_array()) {
            inputs.emplace_back(input.as_object());
        }
        // std::cout << "parse outputs\n";
        for (const auto& output : obj.at("outputs").as_array()) {
            outputs.emplace_back(output.as_object());
        }
    }

};

std::map<
    crypto3::zk::snark::plonk_variable<
        typename crypto3::algebra::curves::pallas::base_field_type::value_type
    >
, std::size_t> comp_counter_form_var;

                template<typename var>
                std::ostream &operator<<(std::ostream &os, const table_piece<var> &inp) {
                    os << "counter: " << inp.counter << "\n";
                    os << "component_name: " << inp.component_name << "\n";
                    os << "start_row: " << inp.start_row << "\n";

                    os << "parent_pieces: ";
                    for (int i = 0; i < inp.parent_pieces.size(); i++) {
                        os << " " << inp.parent_pieces[i];
                    }
                    if (inp.parent_pieces.size() == 0) {
                        os << " empty";
                    }
                    os << "\n";

                    os << "inputs: ";
                    for (int i = 0; i < inp.inputs.size(); i++) {
                        os << " " << inp.inputs[i];
                    }
                    if (inp.inputs.size() == 0) {
                        os << " empty";
                    }
                    os << "\n";

                    os << "outputs: ";
                    for (int i = 0; i < inp.outputs.size(); i++) {
                        os << " " << inp.outputs[i];
                    }
                    if (inp.outputs.size() == 0) {
                        os << " empty";
                    }
                    os << "\n";


                    return os;
                }


std::vector<table_piece<
    crypto3::zk::snark::plonk_variable<
        typename crypto3::algebra::curves::pallas::base_field_type::value_type
    >
>> table_pieces = {}; // TODO: move to assigner


        template<typename BlueprintFieldType, typename table_piece_type, typename ComponentType>
        void call_gen_assignments(
            const table_piece_type &piece,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment
        ) {
            const ComponentType& component_instance = ComponentType(
                    detail::PolicyManager::get_parameters(detail::ManifestReader<ComponentType>::get_witness(0)).witness,
                    std::array<std::uint32_t, 1>{0},
                    std::array<std::uint32_t, 1>{0}
                );

            components::generate_assignments
            (
                component_instance,
                assignment,
                typename ComponentType::input_type{
                    piece.inputs
                },
                piece.start_row
            );
        }

        template<typename BlueprintFieldType, typename table_piece_type>
        void extract_component_type_and_gen_assignments(
            table_piece_type &table_piece,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment
        ) {

            using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
            static std::map<std::string, std::function<void(table_piece_type&, assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>&)>> func_map = {
{"select_instruction unfinished", call_gen_assignments<BlueprintFieldType, table_piece_type, components::select_instruction<ArithmetizationType, BlueprintFieldType>>},
{"load_instruction unfinished",   call_gen_assignments<BlueprintFieldType, table_piece_type, components::store_instruction<ArithmetizationType, BlueprintFieldType>>},
{"poseidon hash",         call_gen_assignments<BlueprintFieldType, table_piece_type, components::poseidon<ArithmetizationType, BlueprintFieldType>>},
{"non-native curve addition", call_gen_assignments<BlueprintFieldType, table_piece_type, components::complete_addition<ArithmetizationType, typename crypto3::algebra::curves::pallas, typename crypto3::algebra::curves::ed25519, basic_non_native_policy<BlueprintFieldType>>>},
// {"non-native curve multiplication", call_gen_assignments<BlueprintFieldType, table_piece_type, components::variable_base_multiplication<ArithmetizationType, typename crypto3::algebra::curves::pallas, typename crypto3::algebra::curves::ed25519, basic_non_native_policy<BlueprintFieldType>>>},
{"native curve addition", call_gen_assignments<BlueprintFieldType, table_piece_type, components::unified_addition<ArithmetizationType, crypto3::algebra::curves::pallas>>},
{"native curve multiplication by shifted const (https://arxiv.org/pdf/math/0208038.pdf)", call_gen_assignments<BlueprintFieldType, table_piece_type, components::curve_element_variable_base_scalar_mul<ArithmetizationType, crypto3::algebra::curves::pallas>>},
// {"bit shift (constant)", call_gen_assignments<BlueprintFieldType, table_piece_type, components::bit_shift_constant<ArithmetizationType>>}, // need to pass Shift into constructor
{"native field division", call_gen_assignments<BlueprintFieldType, table_piece_type, components::division<ArithmetizationType, BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>>},
{"native field multiplication", call_gen_assignments<BlueprintFieldType, table_piece_type, components::multiplication<ArithmetizationType, BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>>},
{"non-native field addition", call_gen_assignments<BlueprintFieldType, table_piece_type, components::addition<ArithmetizationType, typename crypto3::algebra::curves::ed25519::base_field_type, basic_non_native_policy<BlueprintFieldType>>>},
{"non-native field multiplication", call_gen_assignments<BlueprintFieldType, table_piece_type, components::multiplication<ArithmetizationType, typename crypto3::algebra::curves::ed25519::base_field_type, basic_non_native_policy<BlueprintFieldType>>>},

// {"bit_composition", call_gen_assignments<BlueprintFieldType, table_piece_type, components::bit_composition<ArithmetizationType>>}, // unusual constructors, need additional parameters
// {"bit_decomposition", call_gen_assignments<BlueprintFieldType, table_piece_type, components::bit_decomposition<ArithmetizationType>>},
// {"comparison (==, !=)", call_gen_assignments<BlueprintFieldType, table_piece_type, components::comparison_flag<ArithmetizationType>>},
// {"native integer division remainder", call_gen_assignments<BlueprintFieldType, table_piece_type, components::division_remainder<ArithmetizationType>>},
// {"equaluty flag (returns 1 if x==y and 0 otherwise)", call_gen_assignments<BlueprintFieldType, table_piece_type, components::equality_flag<ArithmetizationType, BlueprintFieldType>>},
{"logic_not", call_gen_assignments<BlueprintFieldType, table_piece_type, components::logic_not<ArithmetizationType>>},
{"logic_and", call_gen_assignments<BlueprintFieldType, table_piece_type, components::logic_and<ArithmetizationType>>},
{"logic_or", call_gen_assignments<BlueprintFieldType, table_piece_type, components::logic_or<ArithmetizationType>>},
{"logic_xor", call_gen_assignments<BlueprintFieldType, table_piece_type, components::logic_xor<ArithmetizationType>>},
{"logic_nand", call_gen_assignments<BlueprintFieldType, table_piece_type, components::logic_nand<ArithmetizationType>>},
{"logic_nor", call_gen_assignments<BlueprintFieldType, table_piece_type, components::logic_nor<ArithmetizationType>>},
{"sha512 input preparation component", call_gen_assignments<BlueprintFieldType, table_piece_type, components::reduction<ArithmetizationType, BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>>},
{"non_native field subtraction", call_gen_assignments<BlueprintFieldType, table_piece_type, components::subtraction<ArithmetizationType, BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>>},
{"native field subtraction", call_gen_assignments<BlueprintFieldType, table_piece_type, components::subtraction<ArithmetizationType, BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>>},
{"sha256 hash", call_gen_assignments<BlueprintFieldType, table_piece_type, components::sha256<ArithmetizationType>>},
{"sha512 hash", call_gen_assignments<BlueprintFieldType, table_piece_type, components::sha512<ArithmetizationType>>},
// {"fri array swap component", call_gen_assignments<BlueprintFieldType, table_piece_type, components::fri_array_swap<ArithmetizationType, BlueprintFieldType>>},
// {"fri cosets component", call_gen_assignments<BlueprintFieldType, table_piece_type, components::fri_cosets<ArithmetizationType, BlueprintFieldType>>},
{"fri linear interpolation component", call_gen_assignments<BlueprintFieldType, table_piece_type, components::fri_lin_inter<ArithmetizationType, BlueprintFieldType>>}
// {"gate argument verifier component", call_gen_assignments<BlueprintFieldType, table_piece_type, components::basic_constraints_verifier<ArithmetizationType>>},
// {"lookup argument verifier component", call_gen_assignments<BlueprintFieldType, table_piece_type, components::lookup_verifier<ArithmetizationType>>},
// {"permutation argument verifier component", call_gen_assignments<BlueprintFieldType, table_piece_type, components::permutation_verifier<ArithmetizationType>>}
            };
            auto it = func_map.find(table_piece.component_name);
            if (it != func_map.end()) {
                it->second(table_piece, assignment);
            } else {
                std::cerr << "got component name " << table_piece.component_name << "\n";
                UNREACHABLE("component does not exist!");
            }
            table_piece.done = true;
        }

    }     // namespace blueprint
}    // namespace nil

#endif    // ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_TABLE_PIECE_HPP_
