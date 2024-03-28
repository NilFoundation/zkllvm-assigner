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

#ifndef ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_COMPONENT_MOCKUPS_IS_IN_G2_HPP_
#define ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_COMPONENT_MOCKUPS_IS_IN_G2_HPP_

#include <nil/crypto3/multiprecision/cpp_int/literals.hpp>
#include <nil/crypto3/algebra/matrix/matrix.hpp>
#include <nil/crypto3/algebra/fields/pallas/base_field.hpp>
#include <nil/crypto3/algebra/fields/vesta/base_field.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>


namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType, typename FieldType>
            class is_in_g2;

            template<typename BlueprintFieldType, typename FieldType>
            class is_in_g2<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                           FieldType>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;


                constexpr static const std::size_t gates_amount = 0;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount());
                const std::string component_name = "is_in_g2_unfinished";

                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return is_in_g2::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }


                static manifest_type get_manifest() {
                    using manifest_param = nil::blueprint::manifest_param;
                    using manifest_single_value_param = nil::blueprint::manifest_single_value_param;
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(15)),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount) {
                    return 0;
                }

                struct input_type {
                    std::array<var, 2> X;
                    std::array<var, 2> Y;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        result.insert(result.end(), X.begin(), X.end());
                        result.insert(result.end(), Y.begin(), Y.end());
                        return result;
                    }
                };

                struct result_type {
                    var output;

                    result_type(const is_in_g2<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                                               FieldType> &component,
                                std::uint32_t start_row_index) {
                        output = var(component.W(0), start_row_index, false);
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {output};
                    }
                };


                template<typename ContainerType>
                explicit is_in_g2(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                is_in_g2(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                is_in_g2(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                         std::initializer_list<typename component_type::constant_container_type::value_type>
                             constants,
                         std::initializer_list<typename component_type::public_input_container_type::value_type>
                             public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename BlueprintFieldType, typename FieldType>
            using plonk_is_in_g2 =
                is_in_g2<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                         FieldType>;

            template<typename BlueprintFieldType, typename FieldType>
            typename plonk_is_in_g2<BlueprintFieldType, FieldType>::result_type
                generate_assignments(
                    const plonk_is_in_g2<BlueprintFieldType, FieldType> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &assignment,
                    const typename plonk_is_in_g2<BlueprintFieldType, FieldType>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                using component_type = plonk_is_in_g2<BlueprintFieldType, FieldType>;

                assignment.witness(component.W(0), start_row_index) = 1;

                return typename plonk_is_in_g2<BlueprintFieldType, FieldType>::result_type(
                    component, start_row_index);
            }


            template<typename BlueprintFieldType, typename FieldType>
            typename plonk_is_in_g2<BlueprintFieldType, FieldType>::result_type
                generate_circuit(
                    const plonk_is_in_g2<BlueprintFieldType, FieldType> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &assignment,
                    const typename plonk_is_in_g2<BlueprintFieldType, FieldType>::input_type
                        &instance_input,
                    const std::size_t start_row_index) {

                return typename plonk_is_in_g2<BlueprintFieldType, FieldType>::result_type(
                    component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_IS_IN_G2_HPP
