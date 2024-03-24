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

#ifndef ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_COMPONENT_MOCKUPS_STORE_HPP_
#define ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_COMPONENT_MOCKUPS_STORE_HPP_

#include <cmath>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <utility>
#include <type_traits>
#include <sstream>
#include <string>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType, typename BlueprintFieldType>
            class store_instruction;

            template<typename BlueprintFieldType>
            class store_instruction<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                    BlueprintFieldType>:
                public plonk_component<BlueprintFieldType> {

                static std::size_t rows_amount_internal(std::size_t witness_amount) {
                    return 1;
                }

                static std::size_t gates_amount_internal() {
                    return 1;
                }


            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::size_t witness_amount;

                    gate_manifest_type(std::size_t witness_amount_)
                        : witness_amount(witness_amount_) {}

                    std::uint32_t gates_amount() const override {
                        return store_instruction::gates_amount_internal();
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount
                                                       ) {
                    gate_manifest manifest =
                        gate_manifest(gate_manifest_type(witness_amount));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(
                            new manifest_single_value_param(2)),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount
                                                            ) {
                    return rows_amount_internal(witness_amount);
                }
                constexpr static std::size_t get_empty_rows_amount() {
                    return 1;
                }

                /*
                   It's CRITICAL that these three variables remain on top
                   Otherwise initialization goes in wrong order, leading to arbitrary values.
                */
                constexpr static const std::size_t chunk_size = 2;
                /* Do NOT move the above variables! */

                const std::size_t rows_amount = rows_amount_internal(this->witness_amount());
                const std::size_t empty_rows_amount = get_empty_rows_amount();
                const std::string component_name = "load_instruction unfinished";

                const std::size_t gates_amount = gates_amount_internal();

                struct input_type {
                    var v;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {v};
                    }
                };

                struct result_type {
                    var res;

                    result_type(const store_instruction &component, std::size_t start_row_index) {
                        res = var(component.W(1), start_row_index, false);
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {res};
                    }
                };

                template<typename ContainerType>
                explicit store_instruction(ContainerType witness):
                        component_type(witness, {}, {}, get_manifest())
                        {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                    store_instruction(WitnessContainerType witness, ConstantContainerType constant,
                                    PublicInputContainerType public_input
                                ):
                        component_type(witness, constant, public_input, get_manifest())
                    {};

                store_instruction(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs) :
                        component_type(witnesses, constants, public_inputs, get_manifest()
                    ) {
                };

            };

            template<typename BlueprintFieldType>
            using plonk_load_instruction =
                store_instruction<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                    BlueprintFieldType>;

            template<typename BlueprintFieldType>
            typename plonk_load_instruction<BlueprintFieldType>::result_type
            generate_circuit(
                const plonk_load_instruction<BlueprintFieldType>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_load_instruction<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_index, start_row_index);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_load_instruction<BlueprintFieldType>::result_type(
                            component, start_row_index);
            }

            template<typename BlueprintFieldType>
            std::size_t generate_gates(
                const plonk_load_instruction<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_load_instruction<BlueprintFieldType>::input_type
                    &instance_input) {

                using var = typename plonk_load_instruction<BlueprintFieldType>::var;

                // just mock implementation for keep connectness
                auto constraint_1 = var(component.W(0), 0) - var(component.W(1), 0);

                return bp.add_gate(constraint_1);
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const plonk_load_instruction<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_load_instruction<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_load_instruction<BlueprintFieldType>::var;

                const std::size_t j = start_row_index;
                var input = var(component.W(0), static_cast<int>(j), false);

                bp.add_copy_constraint({instance_input.v, input});
            }

            template<typename BlueprintFieldType>
            typename plonk_load_instruction<BlueprintFieldType>::result_type
            generate_assignments(
                const plonk_load_instruction<BlueprintFieldType>
                    &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_load_instruction<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;

                using component_type = plonk_load_instruction<BlueprintFieldType>;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;

                integral_type input = integral_type(var_value(assignment, instance_input.v).data);

                assignment.witness(component.W(0), row) = input;
                assignment.witness(component.W(1), row) = input;

                return typename component_type::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType>
            typename plonk_load_instruction<BlueprintFieldType>::result_type
            generate_empty_assignments(
                const plonk_load_instruction<BlueprintFieldType>
                    &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_load_instruction<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;

                using component_type = plonk_load_instruction<BlueprintFieldType>;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;

                integral_type input = integral_type(var_value(assignment, instance_input.v).data);

                assignment.witness(component.W(0), row) = input;
                assignment.witness(component.W(1), row) = input;

                return typename component_type::result_type(component, start_row_index);
            }

        }   // namespace components
    }       // namespace blueprint
}   // namespace nil

#endif  // ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_COMPONENT_MOCKUPS_STORE_HPP_
