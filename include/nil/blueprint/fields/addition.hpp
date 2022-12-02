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

#ifndef CRYPTO3_ASSIGNER_FIELD_ADDITION_HPP
#define CRYPTO3_ASSIGNER_FIELD_ADDITION_HPP

#include "llvm/IR/Type.h"
#include "llvm/IR/TypeFinder.h"
#include "llvm/IR/TypedPointerType.h"

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/curves/curve25519.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/component.hpp>
#include <nil/blueprint/basic_non_native_policy.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/addition.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/addition.hpp>

#include <nil/blueprint/stack.hpp>

namespace nil {
    namespace blueprint {
        namespace detail {

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename components::addition<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                BlueprintFieldType, 3, basic_non_native_policy<BlueprintFieldType>>::result_type
                handle_native_field_addition_component(
                    llvm::Value *operand0, llvm::Value *operand1,
                    typename stack_frame<crypto3::zk::snark::plonk_variable<BlueprintFieldType>>::map_type &variables,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    std::uint32_t start_row) {

                using var = crypto3::zk::snark::plonk_variable<BlueprintFieldType>;

                using component_type = components::addition<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    BlueprintFieldType, 3, basic_non_native_policy<BlueprintFieldType>>;
                component_type component_instance({0, 1, 2}, {}, {});

                var x = std::get<0>(variables[operand0]);
                var y = std::get<0>(variables[operand1]);

                components::generate_circuit<BlueprintFieldType, ArithmetizationParams>(component_instance, bp,
                                                                                        assignment, {x, y}, start_row);
                return components::generate_assignments<BlueprintFieldType, ArithmetizationParams>(
                    component_instance, assignment, {x, y}, start_row);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename OperatingFieldType>
            typename components::addition<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                OperatingFieldType, 9, basic_non_native_policy<BlueprintFieldType>>::result_type
                handle_non_native_field_addition_component(
                    llvm::Value *operand0, llvm::Value *operand1,
                    typename stack_frame<crypto3::zk::snark::plonk_variable<BlueprintFieldType>>::map_type &variables,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    std::uint32_t start_row) {

                using var = crypto3::zk::snark::plonk_variable<BlueprintFieldType>;
                using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;

                using component_type = components::addition<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    OperatingFieldType, 9, basic_non_native_policy<BlueprintFieldType>>;
                component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8}, {}, {});

                std::vector<var> operand0_vars = std::get<1>(variables[operand0]);
                std::vector<var> operand1_vars = std::get<1>(variables[operand1]);

                typename non_native_policy_type::template field<OperatingFieldType>::value_type x;
                std::copy_n(operand0_vars.begin(),
                            non_native_policy_type::template field<OperatingFieldType>::ratio,
                            x.begin());

                typename non_native_policy_type::template field<OperatingFieldType>::value_type y;
                std::copy_n(operand1_vars.begin(),
                            non_native_policy_type::template field<OperatingFieldType>::ratio,
                            y.begin());

                components::generate_circuit<BlueprintFieldType, ArithmetizationParams>(component_instance, bp,
                                                                                        assignment, {x, y}, start_row);
                return components::generate_assignments<BlueprintFieldType, ArithmetizationParams>(
                    component_instance, assignment, {x, y}, start_row);
            }

        }    // namespace detail

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        void handle_field_addition_component(
            const llvm::Instruction *inst,
            typename stack_frame<crypto3::zk::snark::plonk_variable<BlueprintFieldType>>::map_type &variables,
            circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
            assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
            std::uint32_t start_row) {

            using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;

            llvm::Value *operand0 = inst->getOperand(0);
            llvm::Value *operand1 = inst->getOperand(1);

            llvm::Type *op0_type = operand0->getType();
            llvm::Type *op1_type = operand1->getType();

            assert(llvm::cast<llvm::GaloisFieldType>(op0_type)->getFieldKind() ==
                   llvm::cast<llvm::GaloisFieldType>(op1_type)->getFieldKind());

            switch (llvm::cast<llvm::GaloisFieldType>(op0_type)->getFieldKind()) {
                case llvm::GALOIS_FIELD_BLS12_381_BASE: {
                    using operating_field_type = typename crypto3::algebra::curves::bls12<381>::base_field_type;

                    if (std::is_same<BlueprintFieldType, operating_field_type>::value) {
                        variables[inst] =
                            detail::handle_native_field_addition_component<BlueprintFieldType, ArithmetizationParams>(
                                operand0, operand1, variables, bp, assignment, start_row)
                                .output;
                    } else {
                        // Non-native bls12-381 is undefined yet
                        // variables[inst] = detail::handle_non_native_field_addition_component<
                        //                       BlueprintFieldType, ArithmetizationParams, operating_field_type>(
                        //                       operand0, operand1, variables, bp, assignment, start_row)
                        //                       .output;
                    }

                    break;
                }
                case llvm::GALOIS_FIELD_PALLAS_BASE: {
                    using operating_field_type = typename crypto3::algebra::curves::pallas::base_field_type;

                    if (std::is_same<BlueprintFieldType, operating_field_type>::value) {
                        variables[inst] =
                            detail::handle_native_field_addition_component<BlueprintFieldType, ArithmetizationParams>(
                                operand0, operand1, variables, bp, assignment, start_row)
                                .output;
                    } else {
                        // Non-native pallas is undefined yet
                        // variables[inst] = detail::handle_non_native_field_addition_component<
                        //                       BlueprintFieldType, ArithmetizationParams, operating_field_type>(
                        //                       operand0, operand1, variables, bp, assignment, start_row)
                        //                       .output;
                    }

                    break;
                }
                case llvm::GALOIS_FIELD_CURVE_25519_BASE: {
                    using operating_field_type = typename crypto3::algebra::curves::ed25519::base_field_type;

                    if (std::is_same<BlueprintFieldType, operating_field_type>::value) {
                        variables[inst] =
                            detail::handle_native_field_addition_component<BlueprintFieldType, ArithmetizationParams>(
                                operand0, operand1, variables, bp, assignment, start_row)
                                .output;
                    } else {
                        typename non_native_policy_type::template field<operating_field_type>::value_type
                            component_result = detail::handle_non_native_field_addition_component<
                                                   BlueprintFieldType, ArithmetizationParams, operating_field_type>(
                                                   operand0, operand1, variables, bp, assignment, start_row)
                                                   .output;

                        variables[inst] = std::vector<crypto3::zk::snark::plonk_variable<BlueprintFieldType>>(
                            std::begin(component_result), std::end(component_result));
                    }

                    break;
                }
                default:
                    assert(1 == 0 && "unsupported field operand type");
            };
        }

    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_FIELD_ADDITION_HPP
