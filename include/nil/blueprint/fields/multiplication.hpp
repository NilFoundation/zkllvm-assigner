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

#ifndef CRYPTO3_ASSIGNER_FIELD_MULTIPLICATION_HPP
#define CRYPTO3_ASSIGNER_FIELD_MULTIPLICATION_HPP

#include "llvm/IR/Type.h"
#include "llvm/IR/TypeFinder.h"
#include "llvm/IR/TypedPointerType.h"

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/curves/curve25519.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>

#include <nil/blueprint/handle_component.hpp>

namespace nil {
    namespace blueprint {
        namespace detail {

            template<typename BlueprintFieldType>
            typename components::multiplication<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>::result_type
                handle_native_field_multiplication_component(
                    llvm::Value *operand0, llvm::Value *operand1,
                    std::map<const llvm::Value *, crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &variables,
                    circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                    assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &assignment,
                    column_type<BlueprintFieldType> &internal_storage,
                    component_calls &statistics,
                    const common_component_parameters& param) {

                using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

                using component_type = components::multiplication<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                    BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

                var x = variables[operand0];
                var y = variables[operand1];
                typename component_type::input_type instance_input({x, y});

                return get_component_result<BlueprintFieldType, component_type>
                    (bp, assignment, internal_storage, statistics, param, instance_input);
            }

            template<typename BlueprintFieldType, typename OperatingFieldType>
            typename components::multiplication<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                OperatingFieldType, basic_non_native_policy<BlueprintFieldType>>::result_type
                handle_non_native_field_multiplication_component(
                    llvm::Value *operand0, llvm::Value *operand1,
                    typename std::map<const llvm::Value *, std::vector<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>> &vectors,
                    circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                    assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &assignment,
                    column_type<BlueprintFieldType> &internal_storage,
                    component_calls &statistics,
                    const common_component_parameters& param) {

                using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
                using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;

                using component_type = components::multiplication<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                    OperatingFieldType, basic_non_native_policy<BlueprintFieldType>>;

                std::vector<var> operand0_vars = vectors[operand0];
                std::vector<var> operand1_vars = vectors[operand1];

                typename non_native_policy_type::template field<OperatingFieldType>::non_native_var_type x;
                std::copy_n(operand0_vars.begin(),
                            non_native_policy_type::template field<OperatingFieldType>::ratio,
                            x.begin());

                typename non_native_policy_type::template field<OperatingFieldType>::non_native_var_type y;
                std::copy_n(operand1_vars.begin(),
                            non_native_policy_type::template field<OperatingFieldType>::ratio,
                            y.begin());
                typename component_type::input_type instance_input({x, y});

                return get_component_result<BlueprintFieldType, component_type>
                    (bp, assignment, internal_storage, statistics, param, instance_input);
            }

        }    // namespace detail

        template<typename BlueprintFieldType>
        void handle_field_multiplication_component(
            const llvm::Instruction *inst,
            stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
            circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                &assignment,
            column_type<BlueprintFieldType> &internal_storage,
            component_calls &statistics,
            const common_component_parameters& param) {

            using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;
            using native_component_type = components::multiplication<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            llvm::Value *operand0 = inst->getOperand(0);
            llvm::Value *operand1 = inst->getOperand(1);

            llvm::Type *op0_type = operand0->getType();
            llvm::Type *op1_type = operand1->getType();

            ASSERT(llvm::cast<llvm::GaloisFieldType>(op0_type)->getFieldKind() ==
                   llvm::cast<llvm::GaloisFieldType>(op1_type)->getFieldKind());

            switch (llvm::cast<llvm::GaloisFieldType>(op0_type)->getFieldKind()) {
                case llvm::GALOIS_FIELD_BLS12381_BASE: {
                    using operating_field_type = typename crypto3::algebra::curves::bls12<381>::base_field_type;

                    if constexpr (non_native_policy_type::template field<operating_field_type>::ratio != 0) {
                        if (std::is_same<BlueprintFieldType, operating_field_type>::value) {
                            const auto res = detail::handle_native_field_multiplication_component<BlueprintFieldType>(
                                                  operand0, operand1, frame.scalars, bp, assignment, internal_storage, statistics, param);
                            handle_component_result<BlueprintFieldType, native_component_type>
                                    (assignment, inst, frame, res, param.gen_mode);
                        } else {
                            UNREACHABLE("non-native bls12-381 base field mul not implemented yet");
                        }
                    }
                    else {
                        UNREACHABLE("non_native_policy is not implemented yet");
                    }

                    break;
                }
                case llvm::GALOIS_FIELD_PALLAS_BASE: {
                    using operating_field_type = typename crypto3::algebra::curves::pallas::base_field_type;

                    if constexpr (non_native_policy_type::template field<operating_field_type>::ratio != 0) {
                        if (std::is_same<BlueprintFieldType, operating_field_type>::value) {
                            const auto res = detail::handle_native_field_multiplication_component<BlueprintFieldType>(
                                                  operand0, operand1, frame.scalars, bp, assignment, internal_storage, statistics, param);
                            handle_component_result<BlueprintFieldType, native_component_type>
                                    (assignment, inst, frame, res, param.gen_mode);
                        } else {
                            UNREACHABLE("non-native pallas base field mul not implemented yet");
                        }
                    }
                    else {
                        UNREACHABLE("non native policy is not implemented yet");
                    }

                    break;
                }
                case llvm::GALOIS_FIELD_CURVE25519_BASE: {
                    using operating_field_type = typename crypto3::algebra::curves::ed25519::base_field_type;
                    using no_native_component_type = components::multiplication<
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                        operating_field_type, basic_non_native_policy<BlueprintFieldType>>;

                    if constexpr (non_native_policy_type::template field<operating_field_type>::ratio != 0) {
                        if (std::is_same<BlueprintFieldType, operating_field_type>::value) {
                            const auto res = detail::handle_native_field_multiplication_component<BlueprintFieldType>(
                                                  operand0, operand1, frame.scalars, bp, assignment, internal_storage, statistics, param);
                            handle_component_result<BlueprintFieldType, native_component_type>
                                    (assignment, inst, frame, res, param.gen_mode);
                        } else {
                            const auto& component_result = detail::handle_non_native_field_multiplication_component<
                                                       BlueprintFieldType, operating_field_type>(
                                                       operand0, operand1, frame.vectors, bp, assignment, internal_storage, statistics, param);

                            handle_component_result<BlueprintFieldType, no_native_component_type>
                                    (assignment, inst, frame, component_result, param.gen_mode);
                        }
                    }
                    else {
                        UNREACHABLE("non_native_policy is not implemented yet");
                    }

                    break;
                }
                default:
                    UNREACHABLE("unsupported field operand type");
            };
        }

    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_FIELD_MULTIPLICATION_HPP
