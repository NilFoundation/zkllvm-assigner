//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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

// #ifndef CRYPTO3_BLUEPRINT_PLONK_COMPARISON_HPP
// #define CRYPTO3_BLUEPRINT_PLONK_COMPARISON_HPP

// #include <nil/crypto3/multiprecision/cpp_int_modular/literals.hpp>
// #include <nil/crypto3/algebra/matrix/matrix.hpp>
// #include <nil/crypto3/algebra/fields/pallas/base_field.hpp>
// #include <nil/crypto3/algebra/fields/vesta/base_field.hpp>

// #include <nil/blueprint/blueprint/plonk/assignment.hpp>
// #include <nil/blueprint/blueprint/plonk/circuit.hpp>
// #include <nil/blueprint/component.hpp>
// #include <nil/blueprint/manifest.hpp>


///////
//---------------------------------------------------------------------------//
// Copyright (c) 2023 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#ifndef ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_COMPONENT_MOCKUPS_COMPARISON_HPP_
#define ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_COMPONENT_MOCKUPS_COMPARISON_HPP_

#include <cmath>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/comparison_mode.hpp>

#include <utility>
#include <type_traits>
#include <sstream>
#include <string>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType, typename BlueprintFieldType>
            class comparison;

            template<typename BlueprintFieldType>
            class comparison<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                    BlueprintFieldType>:
                public plonk_component<BlueprintFieldType> {

                static std::size_t comparisons_per_gate_instance_internal(std::size_t witness_amount) {
                    return 1 + (witness_amount - 3) / 2;
                }

                static std::size_t bits_per_gate_instance_internal(std::size_t witness_amount) {
                    return comparisons_per_gate_instance_internal(witness_amount) * chunk_size;
                }

                static std::size_t rows_amount_internal(std::size_t witness_amount) {
                    return (256 + bits_per_gate_instance_internal(witness_amount) - 1) /
                           bits_per_gate_instance_internal(witness_amount) * 2 +
                           1 + needs_bonus_row_internal(witness_amount);
                }

                static std::size_t gate_instances_internal(std::size_t witness_amount) {
                    return (rows_amount_internal(witness_amount) - 1) / 2;
                }

                static std::size_t padded_chunks_internal(std::size_t witness_amount) {
                    return gate_instances_internal(witness_amount) *
                            comparisons_per_gate_instance_internal(witness_amount);
                }

                static std::size_t padding_bits_internal(std::size_t witness_amount) {
                    return padded_chunks_internal(witness_amount) * chunk_size - 256;
                }

                static std::size_t padding_size_internal(std::size_t witness_amount) {
                    return padding_bits_internal(witness_amount) / chunk_size;
                }

                static std::size_t gates_amount_internal() {
                    return 2 + (256 % chunk_size > 0);
                }

                static std::size_t needs_bonus_row_internal(std::size_t witness_amount) {
                    return witness_amount <= 3;
                }

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::size_t witness_amount;
                    comparison_mode mode;

                    gate_manifest_type(std::size_t witness_amount_, comparison_mode mode_)
                        : witness_amount(witness_amount_), mode(mode_) {}

                    std::uint32_t gates_amount() const override {
                        return comparison::gates_amount_internal();
                    }

                    // bool operator<(const component_gate_manifest* other) const override{
                    //     const gate_manifest_type* other_casted = dynamic_cast<const gate_manifest_type*>(other);
                    //     return witness_amount < other_casted->witness_amount ||
                    //            (witness_amount == other_casted->witness_amount &&
                    //             bits_amount < other_casted->bits_amount) ||
                    //            (witness_amount == other_casted->witness_amount &&
                    //             bits_amount == other_casted->bits_amount &&
                    //             mode < other_casted->mode);
                    // }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       comparison_mode mode) {
                    gate_manifest manifest =
                        gate_manifest(gate_manifest_type(witness_amount, mode));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(
                            new manifest_range_param(3, (BlueprintFieldType::modulus_bits + 28 - 1) / 28 )),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             comparison_mode mode) {
                    return rows_amount_internal(witness_amount);
                }
                constexpr static std::size_t get_empty_rows_amount() {
                    return 1;
                }

                /*
                   It's CRITICAL that these three variables remain on top
                   Otherwise initialization goes in wrong order, leading to arbitrary values.
                */
                const comparison_mode mode;
                constexpr static const std::size_t chunk_size = 2;
                /* Do NOT move the above variables! */

                const std::size_t comparisons_per_gate_instance =
                    comparisons_per_gate_instance_internal(this->witness_amount());
                const std::size_t bits_per_gate_instance =
                    bits_per_gate_instance_internal(this->witness_amount());
                const bool needs_bonus_row = needs_bonus_row_internal(this->witness_amount());

                const std::size_t rows_amount = rows_amount_internal(this->witness_amount());
                const std::size_t empty_rows_amount = get_empty_rows_amount();
                const std::string component_name = "comparison_unfinished";


                const std::size_t gate_instances = gate_instances_internal(this->witness_amount());
                const std::size_t padded_chunks = padded_chunks_internal(this->witness_amount());
                const std::size_t padding_bits = padding_bits_internal(this->witness_amount());
                const std::size_t padding_size = padding_size_internal(this->witness_amount());

                const std::size_t gates_amount = gates_amount_internal();

                struct input_type {
                    var x, y;

                    input_type(const std::vector<var>& input_vect) {
                        if (input_vect.size() != 2) {
                            throw std::out_of_range("Vector size does not match input size");
                        }
                        x = input_vect[0];
                        y = input_vect[1];
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {x, y};
                    }
                };

                struct result_type {
                    var flag;

                    result_type(const comparison &component, std::size_t start_row_index) {
                        flag = var(component.W(0), start_row_index, false);
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {flag};
                    }
                };

                template<typename ContainerType>
                explicit comparison(ContainerType witness, comparison_mode mode_):
                        component_type(witness, {}, {}, get_manifest()),
                        mode(mode_) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                    comparison(WitnessContainerType witness, ConstantContainerType constant,
                                    PublicInputContainerType public_input,
                                    comparison_mode mode_):
                        component_type(witness, constant, public_input, get_manifest()),
                        mode(mode_) {
                };

                comparison(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                        comparison_mode mode_) :
                        component_type(witnesses, constants, public_inputs, get_manifest()),
                        mode(mode_) {
                };

            };

            template<typename BlueprintFieldType>
            using plonk_comparison =
                comparison<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                    BlueprintFieldType>;

            template<typename BlueprintFieldType>
                typename plonk_comparison<BlueprintFieldType>::result_type
                generate_circuit(
                    const plonk_comparison<BlueprintFieldType>
                        &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &assignment,
                    const typename plonk_comparison<BlueprintFieldType>::input_type
                        &instance_input,
                    const std::uint32_t start_row_index) {

                    return typename plonk_comparison<BlueprintFieldType>::result_type(
                                component, start_row_index);
                }

                template<typename BlueprintFieldType>
                typename plonk_comparison<BlueprintFieldType>::result_type
                generate_assignments(
                    const plonk_comparison<BlueprintFieldType>
                        &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &assignment,
                    const typename plonk_comparison<BlueprintFieldType>::input_type
                        &instance_input,
                    const std::uint32_t start_row_index) {

                    std::size_t row = start_row_index;

                    using component_type = plonk_comparison<BlueprintFieldType>;
                    using value_type = typename BlueprintFieldType::value_type;
                    using integral_type = typename BlueprintFieldType::integral_type;

                    integral_type x = integral_type(var_value(assignment, instance_input.x).data);
                    integral_type y = integral_type(var_value(assignment, instance_input.y).data);

                    assignment.witness(component.W(1), row) = x;
                    assignment.witness(component.W(2), row) = y;

                    bool output;
                    switch (component.mode) {
                        case comparison_mode::LESS_THAN:
                            output = (x < y);
                            break;
                        case comparison_mode::LESS_EQUAL:
                            output = (x <= y);
                            break;
                        case comparison_mode::GREATER_THAN:
                            output = (x > y);
                            break;
                        case comparison_mode::GREATER_EQUAL:
                            output = (x >= y);
                            break;
                        case comparison_mode::FLAG:
                            UNREACHABLE("invalid comparison mode");
                            break;
                    }

                    assignment.witness(component.W(0), row) = output;

                    return typename component_type::result_type(component, start_row_index);
                }

                template<typename BlueprintFieldType>
                typename plonk_comparison<BlueprintFieldType>::result_type
                generate_empty_assignments(
                    const plonk_comparison<BlueprintFieldType>
                        &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &assignment,
                    const typename plonk_comparison<BlueprintFieldType>::input_type
                        &instance_input,
                    const std::uint32_t start_row_index) {
                    std::size_t row = start_row_index;

                    using component_type = plonk_comparison<BlueprintFieldType>;
                    using value_type = typename BlueprintFieldType::value_type;
                    using integral_type = typename BlueprintFieldType::integral_type;

                    integral_type x = integral_type(var_value(assignment, instance_input.x).data);
                    integral_type y = integral_type(var_value(assignment, instance_input.y).data);

                    assignment.witness(component.W(1), row) = x;
                    assignment.witness(component.W(2), row) = y;

                    bool output;
                    switch (component.mode) {
                        case comparison_mode::LESS_THAN:
                            output = (x < y);
                            break;
                        case comparison_mode::LESS_EQUAL:
                            output = (x <= y);
                            break;
                        case comparison_mode::GREATER_THAN:
                            output = (x > y);
                            break;
                        case comparison_mode::GREATER_EQUAL:
                            output = (x >= y);
                            break;
                        case comparison_mode::FLAG:
                            UNREACHABLE("invalid comparison mode");
                            break;
                    }

                    assignment.witness(component.W(0), row) = output;

                    return typename component_type::result_type(component, start_row_index);
            }

        }   // namespace components
    }       // namespace blueprint
}   // namespace nil

#endif  // ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_COMPONENT_MOCKUPS_COMPARISON_HPP_
