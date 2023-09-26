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

#ifndef CRYPTO3_ASSIGNER_CURVE_MULTIPLICATION_HPP
#define CRYPTO3_ASSIGNER_CURVE_MULTIPLICATION_HPP

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
#include <nil/blueprint/components/algebra/curves/pasta/plonk/variable_base_scalar_mul.hpp>
#include <nil/blueprint/components/algebra/curves/edwards/plonk/non_native/variable_base_multiplication.hpp>

#include <nil/blueprint/asserts.hpp>
#include <nil/blueprint/stack.hpp>

namespace nil {
    namespace blueprint {
        namespace detail {

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
            typename components::curve_element_variable_base_scalar_mul<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                CurveType>::result_type
                handle_native_curve_non_native_scalar_multiplication_component(
                    llvm::Value *operand_curve, llvm::Value *operand_field,
                    typename std::map<const llvm::Value *, std::vector<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>> &vectors,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    std::uint32_t start_row) {

                using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

                using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                using component_type = components::curve_element_variable_base_scalar_mul<
                    ArithmetizationType,CurveType>;
                component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, {0}, {});

                struct var_ec_point {
                    var X;
                    var Y;
                };

                var_ec_point T = {vectors[operand_curve][0], vectors[operand_curve][1]};
                std::vector<var> b = {vectors[operand_field][0], vectors[operand_field][1]};

                typename component_type::input_type addition_input = {{T.X, T.Y}, b[0], b[1]};

                components::generate_circuit(component_instance, bp, assignment, addition_input, start_row);
                return components::generate_assignments(component_instance, assignment, addition_input, start_row);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType, typename Ed25519Type>
            typename components::variable_base_multiplication<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                CurveType,
                Ed25519Type,
                basic_non_native_policy<BlueprintFieldType>>::result_type
                handle_non_native_curve_native_scalar_multiplication_component(
                    llvm::Value *operand_curve,
                    llvm::Value *operand_field,
                    typename std::map<const llvm::Value *, std::vector<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>> &vectors,
                    typename std::map<const llvm::Value *, crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &variables,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    std::uint32_t start_row) {

                using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

                using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                using component_type = components::variable_base_multiplication<ArithmetizationType, CurveType,
                            Ed25519Type, basic_non_native_policy<BlueprintFieldType>>;
                component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8}, {0}, {});

                using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;

                struct var_ec_point {
                    typename non_native_policy_type::template field<typename Ed25519Type::base_field_type>::non_native_var_type X;
                    typename non_native_policy_type::template field<typename Ed25519Type::base_field_type>::non_native_var_type Y;
                };

                var_ec_point T = {
                    {vectors[operand_curve][0],
                     vectors[operand_curve][1],
                     vectors[operand_curve][2],
                     vectors[operand_curve][3]},
                    {
                     vectors[operand_curve][4],
                     vectors[operand_curve][5],
                     vectors[operand_curve][6],
                     vectors[operand_curve][7]}};

                var b = variables[operand_field];

                typename component_type::input_type addition_input = {{T.X, T.Y}, b};

                components::generate_circuit(component_instance, bp, assignment, addition_input, start_row);
                return components::generate_assignments(component_instance, assignment, addition_input, start_row);
            }

        }    // namespace detail

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        void handle_curve_multiplication_component(
            const llvm::Instruction *inst,
            stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
            circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
            assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
            std::uint32_t start_row) {

            using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;

            unsigned curve_nr, field_nr;
            for (unsigned i = 0; i < 2; i++) {
                if (inst->getOperand(i)->getType()->isFieldTy()) {
                    field_nr = i;
                }
                if (inst->getOperand(i)->getType()->isCurveTy()) {
                    curve_nr = i;
                }
            }

            llvm::Value *operand_curve = inst->getOperand(curve_nr);
            llvm::Value *operand_field = inst->getOperand(field_nr);

            llvm::Type *op_curve_type = operand_curve->getType();
            llvm::Type *op_field_type = operand_field->getType();

            switch (llvm::cast<llvm::EllipticCurveType>(op_curve_type)->getCurveKind()) {
                case llvm::ELLIPTIC_CURVE_VESTA: {
                    using operating_curve_type = crypto3::algebra::curves::vesta;
                    using operating_field_type = operating_curve_type::base_field_type;

                    ASSERT(llvm::cast<llvm::GaloisFieldType>(op_field_type)->getFieldKind() == llvm::GALOIS_FIELD_VESTA_SCALAR);

                    if (std::is_same<BlueprintFieldType, operating_field_type>::value) {
                        UNREACHABLE("native vesta multiplication is not implemented");
                    } else {
                        UNREACHABLE("non-native vesta multiplication is not implemented");
                    }

                    break;
                }

                case llvm::ELLIPTIC_CURVE_PALLAS: {
                    ASSERT(llvm::cast<llvm::GaloisFieldType>(op_field_type)->getFieldKind() == llvm::GALOIS_FIELD_PALLAS_SCALAR);

                    using operating_curve_type = crypto3::algebra::curves::pallas;
                    using operating_field_type = operating_curve_type::base_field_type;

                    if (std::is_same<BlueprintFieldType, operating_field_type>::value) {
                        using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                        using component_type = components::curve_element_variable_base_scalar_mul<
                                ArithmetizationType, operating_curve_type>;
                        typename component_type::result_type res =
                            detail::handle_native_curve_non_native_scalar_multiplication_component<BlueprintFieldType, ArithmetizationParams, operating_curve_type>(
                                operand_curve, operand_field, frame.vectors, bp, assignment, start_row);
                        std::vector<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> res_vector = {res.X, res.Y};
                        frame.vectors[inst] = res_vector;
                    } else {
                        UNREACHABLE("non-native pallas multiplication is not implemented");
                    }

                    break;
                }

                case llvm::ELLIPTIC_CURVE_CURVE25519: {
                    ASSERT(llvm::cast<llvm::GaloisFieldType>(op_field_type)->getFieldKind() == llvm::GALOIS_FIELD_CURVE25519_SCALAR);

                    using operating_curve_type = typename crypto3::algebra::curves::ed25519;
                    using operating_field_type = operating_curve_type::base_field_type;

                    using pallas_curve_type = typename crypto3::algebra::curves::pallas;
                    if (!std::is_same<BlueprintFieldType, pallas_curve_type::base_field_type>::value) {
                        UNREACHABLE("pallas_curve_type is used as template parameter, if BlueprintFieldType is not pallas::base_field_type, then code must be re-written");
                    }

                    if (std::is_same<BlueprintFieldType, operating_field_type>::value) {
                        UNREACHABLE("native curve25519 multiplication is not implemented");
                    } else {
                        using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                        using component_type = components::variable_base_multiplication<ArithmetizationType, pallas_curve_type,
                            operating_curve_type, basic_non_native_policy<BlueprintFieldType>>;
                        typename component_type::result_type res =
                            detail::handle_non_native_curve_native_scalar_multiplication_component<BlueprintFieldType, ArithmetizationParams, pallas_curve_type, operating_curve_type>(
                                operand_curve,
                                operand_field,
                                frame.vectors,
                                frame.scalars,
                                bp,
                                assignment,
                                start_row);

                        std::vector<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> res_vector =
                        {
                            res.output.x[0],
                            res.output.x[1],
                            res.output.x[2],
                            res.output.x[3],
                            res.output.y[0],
                            res.output.y[1],
                            res.output.y[2],
                            res.output.y[3]
                        };

                        frame.vectors[inst] = std::vector<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>(
                            std::begin(res_vector), std::end(res_vector));
                    }

                    break;
                }

                case llvm::ELLIPTIC_CURVE_BLS12381: {
                    ASSERT(llvm::cast<llvm::GaloisFieldType>(op_field_type)->getFieldKind() == llvm::GALOIS_FIELD_BLS12381_SCALAR);

                    using operating_field_type = typename crypto3::algebra::curves::bls12<381>::base_field_type;

                    if (std::is_same<BlueprintFieldType, operating_field_type>::value) {
                        UNREACHABLE("native bls12381 multiplication is not implemented");
                    } else {
                        UNREACHABLE("non-native bls12381 multiplication is not implemented");
                    }

                    break;
                }

                default:
                    UNREACHABLE("unsupported field operand type");
            };
        }

    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_CURVE_MULTIPLICATION_HPP
