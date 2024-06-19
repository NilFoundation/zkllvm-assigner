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

#ifndef ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_CALL_GEN_ASSIGNMENTS_HPP_
#define ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_CALL_GEN_ASSIGNMENTS_HPP_

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
#include <condition_variable>
#include <mutex>
#include <thread>
#include <atomic>

namespace nil {
    namespace blueprint {

        std::string extract_word_and_pop(std::string& word) {
            std::size_t delimiter = word.find('\n');
            std::string first = word.substr(0, delimiter);
            word = word.substr(delimiter + 1, word.size() - delimiter - 1);
            return first;
        }

        template<typename BlueprintFieldType, typename table_piece_type, typename ComponentType>
        void call_gen_assignments(
            const table_piece_type &piece,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment
        ) {
            const ComponentType& component_instance = ComponentType(
                    detail::PolicyManager::get_parameters(detail::ManifestReader<ComponentType>::get_witness()).witness,
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

        template<typename BlueprintFieldType, typename table_piece_type, typename ComponentType>
        void call_gen_assignments_bool(
            const table_piece_type &piece,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment
        ) {
            std::string line = piece.non_standard_constructor_parameters;
            bool inequal = std::stoi(extract_word_and_pop(line));

            const ComponentType component_instance(
                    detail::PolicyManager::get_parameters(detail::ManifestReader<ComponentType>::get_witness(inequal)).witness,
                    std::array<std::uint32_t, 1>{0},
                    std::array<std::uint32_t, 1>{0},
                    inequal
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

        template<typename BlueprintFieldType, typename table_piece_type, typename ComponentType>
        void call_gen_assignments_int(
            const table_piece_type &piece,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment
        ) {
            std::string line = piece.non_standard_constructor_parameters;
            std::size_t size = std::stoi(extract_word_and_pop(line));

            const ComponentType component_instance(
                    detail::PolicyManager::get_parameters(detail::ManifestReader<ComponentType>::get_witness(size)).witness,
                    std::array<std::uint32_t, 1>{0},
                    std::array<std::uint32_t, 1>{0},
                    size
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

        template<typename BlueprintFieldType, typename table_piece_type, typename ComponentType>
        void call_gen_assignments_leq(
            const table_piece_type &piece,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment
        ) {
            std::string line = piece.non_standard_constructor_parameters;

            std::size_t bits_amount = std::stoi(extract_word_and_pop(line));
            typename nil::blueprint::components::comparison_mode mode =
                static_cast<typename nil::blueprint::components::comparison_mode>(std::stoi(extract_word_and_pop(line)));

            const ComponentType component_instance(
                    detail::PolicyManager::get_parameters(detail::ManifestReader<ComponentType>::get_witness(bits_amount, mode)).witness,
                    std::array<std::uint32_t, 1>{0},
                    std::array<std::uint32_t, 1>{0},
                    bits_amount,
                    mode
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

        template<typename BlueprintFieldType, typename table_piece_type, typename ComponentType>
        void call_gen_assignments_div_rem(
            const table_piece_type &piece,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment
        ) {
            std::string line = piece.non_standard_constructor_parameters;

            std::size_t bits_amount = std::stoi(extract_word_and_pop(line));
            bool check_inputs = std::stoi(extract_word_and_pop(line));

            const ComponentType component_instance(
                    detail::PolicyManager::get_parameters(detail::ManifestReader<ComponentType>::get_witness(bits_amount, check_inputs)).witness,
                    std::array<std::uint32_t, 1>{0},
                    std::array<std::uint32_t, 1>{0},
                    bits_amount,
                    check_inputs
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

        template<typename BlueprintFieldType, typename table_piece_type, typename ComponentType>
        void call_gen_assignments_bit_shift(
            const table_piece_type &piece,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment
        ) {
            std::string line = piece.non_standard_constructor_parameters;

            std::size_t bits_amount = std::stoi(extract_word_and_pop(line));
            const std::uint32_t shift = std::stoi(extract_word_and_pop(line));

            typename nil::blueprint::components::bit_shift_mode mode =
                static_cast<typename nil::blueprint::components::bit_shift_mode>(
                    std::stoi(extract_word_and_pop(line)));

            const ComponentType component_instance(
                    detail::PolicyManager::get_parameters(detail::ManifestReader<ComponentType>::get_witness(bits_amount, shift, mode)).witness,
                    std::array<std::uint32_t, 1>{0},
                    std::array<std::uint32_t, 1>{0},
                    bits_amount,
                    shift,
                    mode
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

        template<typename BlueprintFieldType, typename table_piece_type, typename ComponentType>
        void call_gen_assignments_bit_comp(
            const table_piece_type &piece,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment
        ) {
            std::string line = piece.non_standard_constructor_parameters;

            std::size_t bits_amount = std::stoi(extract_word_and_pop(line));
            bool check_input = std::stoi(extract_word_and_pop(line));

            typename nil::blueprint::components::bit_composition_mode mode =
                static_cast<typename nil::blueprint::components::bit_composition_mode>(
                    std::stoi(extract_word_and_pop(line)));

            const ComponentType component_instance(
                    detail::PolicyManager::get_parameters(detail::ManifestReader<ComponentType>::get_witness(bits_amount, check_input, mode)).witness,
                    std::array<std::uint32_t, 1>{0},
                    std::array<std::uint32_t, 1>{0},
                    bits_amount,
                    check_input,
                    mode
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

        template<typename BlueprintFieldType, typename table_piece_type, typename ComponentType>
        void call_gen_assignments_bits_amount_composition_mode(
            const table_piece_type &piece,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment
        ) {
            std::string line = piece.non_standard_constructor_parameters;
            std::size_t bits_amount = std::stoi(extract_word_and_pop(line));

            typename nil::blueprint::components::bit_composition_mode mode =
                static_cast<typename nil::blueprint::components::bit_composition_mode>(
                    std::stoi(extract_word_and_pop(line)));

            const ComponentType component_instance(
                    detail::PolicyManager::get_parameters(detail::ManifestReader<ComponentType>::get_witness(bits_amount, mode)).witness,
                    std::array<std::uint32_t, 1>{0},
                    std::array<std::uint32_t, 1>{0},
                    bits_amount,
                    mode
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


        template<typename BlueprintFieldType, typename table_piece_type, typename ComponentType>
        void call_gen_assignments_fri_cosets(
            const table_piece_type &piece,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment
        ) {
            std::string line = piece.non_standard_constructor_parameters;

            std::size_t size = std::stoi(extract_word_and_pop(line));
            std::string omega_str = extract_word_and_pop(line);

            typename BlueprintFieldType::value_type omega = 0;
            typename BlueprintFieldType::value_type intermediate = 0;

            for (int i = 0; i < omega_str.size(); ++i) {
                intermediate = int(omega_str[omega_str.size() - 1 - i] - '0');
                for (std::size_t j = 0; j < i; j++) {
                    intermediate *= 10;
                }
                omega += intermediate;
            }

            const ComponentType component_instance(
                    detail::PolicyManager::get_parameters(detail::ManifestReader<ComponentType>::get_witness(size, omega)).witness,
                    std::array<std::uint32_t, 1>{0},
                    std::array<std::uint32_t, 1>{0},
                    size,
                    omega
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

        std::vector<std::size_t> vect_from_string(std::string word) {
            std::vector<std::size_t> vec;
            std::istringstream iss(word);
            std::size_t num;
            while (iss >> num) {
                vec.push_back(num);
            }
            return vec;

        }


        template<typename BlueprintFieldType, typename table_piece_type, typename ComponentType>
        void call_gen_assignments_gate_arg(
            const table_piece_type &piece,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment
        ) {
            std::string line = piece.non_standard_constructor_parameters;

            std::vector<std::size_t> gate_sizes = vect_from_string(extract_word_and_pop(line));

            const ComponentType component_instance(
                    detail::PolicyManager::get_parameters(detail::ManifestReader<ComponentType>::get_witness(gate_sizes)).witness,
                    std::array<std::uint32_t, 1>{0},
                    std::array<std::uint32_t, 1>{0},
                    gate_sizes
                );

            std::vector<std::size_t> input_vectors_lengths = vect_from_string(extract_word_and_pop(line));

            components::generate_assignments
            (
                component_instance,
                assignment,
                typename ComponentType::input_type{
                    piece.inputs, input_vectors_lengths,
                },
                piece.start_row
            );
        }


        template<typename BlueprintFieldType, typename table_piece_type, typename ComponentType>
        void call_gen_assignments_lookup(
            const table_piece_type &piece,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment
        ) {
            std::string line = piece.non_standard_constructor_parameters;

            std::size_t num0 = std::stoi(extract_word_and_pop(line));
            std::vector<std::size_t> vec1 = vect_from_string(extract_word_and_pop(line));
            std::vector<std::size_t> vec2 = vect_from_string(extract_word_and_pop(line));

            std::size_t num3 = std::stoi(extract_word_and_pop(line));
            std::vector<std::size_t> vec4 = vect_from_string(extract_word_and_pop(line));
            std::vector<std::size_t> vec5 = vect_from_string(extract_word_and_pop(line));


            const ComponentType component_instance(
                    detail::PolicyManager::get_parameters(detail::ManifestReader<ComponentType>::get_witness(num0, vec1, vec2, num3, vec4, vec5)).witness,
                    std::array<std::uint32_t, 1>{0},
                    std::array<std::uint32_t, 1>{0},
                    num0, vec1, vec2, num3, vec4, vec5
                );


            std::vector<std::size_t> imput_vectors_lengths = vect_from_string(extract_word_and_pop(line));

            components::generate_assignments
            (
                component_instance,
                assignment,
                typename ComponentType::input_type{
                    piece.inputs, imput_vectors_lengths,
                },
                piece.start_row
            );
        }

    }     // namespace blueprint
}    // namespace nil

#endif    // ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_CALL_GEN_ASSIGNMENTS_HPP_
