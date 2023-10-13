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

#ifndef CRYPTO3_ASSIGNER_CURVE_ADDITION_HPP
#define CRYPTO3_ASSIGNER_CURVE_ADDITION_HPP

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
#include <nil/blueprint/components/algebra/curves/pasta/plonk/unified_addition.hpp>
#include <nil/blueprint/components/algebra/curves/edwards/plonk/non_native/complete_addition.hpp>

#include <nil/blueprint/asserts.hpp>
#include <nil/blueprint/stack.hpp>
#include <nil/blueprint/policy/policy_manager.hpp>

namespace nil {
    namespace blueprint {
        namespace detail {

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
            typename components::unified_addition<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                CurveType>::result_type
                handle_native_curve_unified_addition_component(
                    llvm::Value *operand0, llvm::Value *operand1,
                    typename std::map<const llvm::Value *, std::vector<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>> &vectors,
                    circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    std::uint32_t start_row) {

                using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

                using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                using component_type = components::unified_addition<ArithmetizationType, CurveType>;
                const auto p = PolicyManager::get_parameters(ManifestReader<component_type, ArithmetizationParams>::get_witness(0));
                component_type component_instance(p.witness, ManifestReader<component_type, ArithmetizationParams>::get_constants(), ManifestReader<component_type, ArithmetizationParams>::get_public_inputs());

                struct var_ec_point {
                    var X;
                    var Y;
                };

                var_ec_point P = {vectors[operand0][0], vectors[operand0][1]};
                var_ec_point Q = {vectors[operand1][0], vectors[operand1][1]};

                typename component_type::input_type addition_input = {{P.X, P.Y}, {Q.X, Q.Y}};

                components::generate_circuit(component_instance, bp, assignment, addition_input, start_row);
                return components::generate_assignments(
                            component_instance, assignment, addition_input, start_row);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType, typename Ed25519Type>
            typename components::complete_addition<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                CurveType,
                Ed25519Type,
                basic_non_native_policy<BlueprintFieldType>>::result_type
                handle_non_native_curve_addition_component(
                    llvm::Value *operand0, llvm::Value *operand1,
                    typename std::map<const llvm::Value *, std::vector<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>> &vectors,
                    circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    std::uint32_t start_row) {

                using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

                using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                using component_type = components::complete_addition<ArithmetizationType, CurveType,
                            Ed25519Type, basic_non_native_policy<BlueprintFieldType>>;
                const auto p = PolicyManager::get_parameters(ManifestReader<component_type, ArithmetizationParams>::get_witness(0));
                component_type component_instance(p.witness, ManifestReader<component_type, ArithmetizationParams>::get_constants(), ManifestReader<component_type, ArithmetizationParams>::get_public_inputs());

                using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;

                struct var_ec_point {
                    typename non_native_policy_type::template field<typename Ed25519Type::base_field_type>::non_native_var_type X;
                    typename non_native_policy_type::template field<typename Ed25519Type::base_field_type>::non_native_var_type Y;
                };

                var_ec_point P = {
                    {
                        vectors[operand0][0],
                        vectors[operand0][1],
                        vectors[operand0][2],
                        vectors[operand0][3]
                    }, {
                        vectors[operand0][4],
                        vectors[operand0][5],
                        vectors[operand0][6],
                        vectors[operand0][7]}};

                var_ec_point Q = {
                    {
                        vectors[operand1][0],
                        vectors[operand1][1],
                        vectors[operand1][2],
                        vectors[operand1][3]
                    }, {
                        vectors[operand1][4],
                        vectors[operand1][5],
                        vectors[operand1][6],
                        vectors[operand1][7]}};

                typename component_type::input_type addition_input = {{P.X, P.Y}, {Q.X, Q.Y}};

                components::generate_circuit(component_instance, bp, assignment, addition_input, start_row);
                return components::generate_assignments(
                            component_instance, assignment, addition_input, start_row);
            }
        }    // namespace detail

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        void handle_curve_addition_component(
            const llvm::Instruction *inst,
            stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
            circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
            std::uint32_t start_row, bool next_prover) {

            using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;

            llvm::Value *operand0 = inst->getOperand(0);
            llvm::Value *operand1 = inst->getOperand(1);

            llvm::Type *op0_type = operand0->getType();
            llvm::Type *op1_type = operand1->getType();

            ASSERT(llvm::cast<llvm::EllipticCurveType>(op0_type)->getCurveKind() ==
                   llvm::cast<llvm::EllipticCurveType>(op1_type)->getCurveKind());

            switch (llvm::cast<llvm::EllipticCurveType>(op0_type)->getCurveKind()) {
                case llvm::ELLIPTIC_CURVE_PALLAS: {
                    using operating_curve_type = crypto3::algebra::curves::pallas;
                    using operating_field_type = typename operating_curve_type::base_field_type;

                    if (std::is_same<BlueprintFieldType, operating_field_type>::value) {
                        using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                        using component_type = components::unified_addition<ArithmetizationType, operating_curve_type>;
                        typename component_type::result_type res =
                            detail::handle_native_curve_unified_addition_component<BlueprintFieldType, ArithmetizationParams, operating_curve_type>(
                                operand0, operand1, frame.vectors, bp, assignment, start_row);
                        std::vector<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> res_vector = {res.X, res.Y};
                        if (next_prover) {
                            frame.vectors[inst] = save_shared_var(assignment, res_vector);
                        } else {
                            frame.vectors[inst] = res_vector;
                        }
                    } else {
                        UNREACHABLE("non-native pallas is undefined");
                    }

                    break;
                }

                case llvm::ELLIPTIC_CURVE_VESTA: {
                    using operating_curve_type = crypto3::algebra::curves::vesta;
                    using operating_field_type = operating_curve_type::base_field_type;

                    if (std::is_same<BlueprintFieldType, operating_field_type>::value) {
                        UNREACHABLE("native vesta is not implemented");
                    } else {
                         UNREACHABLE("non-native vesta is undefined");
                    }

                    break;
                }

                case llvm::ELLIPTIC_CURVE_CURVE25519: {
                    using operating_curve_type = typename crypto3::algebra::curves::ed25519;
                    using operating_field_type = operating_curve_type::base_field_type;
                    using pallas_curve_type = typename crypto3::algebra::curves::pallas;
                    if (!std::is_same<BlueprintFieldType, pallas_curve_type::base_field_type>::value) {
                        UNREACHABLE("pallas_curve_type is used as template parameter, if BlueprintFieldType is not pallas::base_field_type, then code must be re-written");
                    }

                    if (std::is_same<BlueprintFieldType, operating_field_type>::value) {
                        UNREACHABLE("native curve25519 addition is not implemented");
                    } else {
                        using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                        using component_type = components::complete_addition<ArithmetizationType, pallas_curve_type,
                            operating_curve_type, basic_non_native_policy<BlueprintFieldType>>;
                        typename component_type::result_type res =
                            detail::handle_non_native_curve_addition_component<BlueprintFieldType, ArithmetizationParams, pallas_curve_type, operating_curve_type>(
                                operand0, operand1, frame.vectors, bp, assignment, start_row);
                        std::vector<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> res_vector = {
                            res.output.x[0],
                            res.output.x[1],
                            res.output.x[2],
                            res.output.x[3],
                            res.output.y[0],
                            res.output.y[1],
                            res.output.y[2],
                            res.output.y[3]};
                        frame.vectors[inst] = res_vector;
                        if (next_prover) {
                            frame.vectors[inst] = save_shared_var(assignment, res_vector);
                        } else {
                            frame.vectors[inst] = res_vector;
                        }
                    }

                    break;
                }

                case llvm::ELLIPTIC_CURVE_BLS12381: {
                    using operating_field_type = typename crypto3::algebra::curves::bls12<381>::base_field_type;

                    if (std::is_same<BlueprintFieldType, operating_field_type>::value) {
                        UNREACHABLE("native bls12381 addition is not implemented");
                    } else {
                        UNREACHABLE("non-native bls12381 addition is not implemented");
                    }

                    break;
                }


                default:
                    UNREACHABLE("unsupported field operand type");
            };
        }

    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_CURVE_ADDITION_HPP
