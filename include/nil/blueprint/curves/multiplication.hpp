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
#include <nil/blueprint/components/algebra/curves/pasta/plonk/variable_base_scalar_mul_15_wires.hpp>
#include <nil/blueprint/components/algebra/curves/pasta/plonk/decomposed_variable_base_scalar_mul_15_wires.hpp>

#include <nil/blueprint/stack.hpp>

namespace nil {
    namespace blueprint {
        namespace detail {

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
            typename components::curve_element_decomposed_variable_base_scalar_mul<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                CurveType, 15>::result_type
                handle_native_curve_non_native_scalar_multiplication_component(
                    llvm::Value *operand_curve, llvm::Value *operand_field,
                    typename std::map<const llvm::Value *, std::vector<crypto3::zk::snark::plonk_variable<BlueprintFieldType>>> &vectors,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    std::uint32_t start_row) {

                using var = crypto3::zk::snark::plonk_variable<BlueprintFieldType>;

                using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                using component_type = components::curve_element_decomposed_variable_base_scalar_mul<
                    ArithmetizationType,CurveType, 15>;
                component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, {0}, {});

                struct var_ec_point {
                    var X;
                    var Y;
                };

                var_ec_point T = {vectors[operand_curve][0], vectors[operand_curve][1]};
                std::vector<var> b = {vectors[operand_field][0], vectors[operand_field][1]};

                typename component_type::input_type addition_input = {{T.X, T.Y}, b[0], b[1]};

                components::generate_circuit_decomposed_vbsm<BlueprintFieldType, ArithmetizationParams>(component_instance, bp,
                                                                                        assignment, addition_input, start_row);
                return components::generate_assignments_decomposed_vbsm<BlueprintFieldType, ArithmetizationParams>(
                    component_instance, assignment, addition_input, start_row);
            }
            
        }    // namespace detail

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        void handle_curve_multiplication_component(
            const llvm::Instruction *inst,
            stack_frame<crypto3::zk::snark::plonk_variable<BlueprintFieldType>> &frame,
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
                    using operating_curve_type = typename crypto3::algebra::curves::vesta;
                    using operating_field_type = operating_curve_type::base_field_type;

                    assert(llvm::cast<llvm::GaloisFieldType>(op_field_type)->getFieldKind() == llvm::GALOIS_FIELD_VESTA_SCALAR);

                    if (std::is_same<BlueprintFieldType, operating_field_type>::value) {
                        assert(1==0 && "native vesta multiplication is not implemented");
                    } else {
                        assert(1==0 && "non-native vesta multiplication is not implemented");
                    }

                    break;
                }

                case llvm::ELLIPTIC_CURVE_PALLAS: {
                    assert(llvm::cast<llvm::GaloisFieldType>(op_field_type)->getFieldKind() == llvm::GALOIS_FIELD_PALLAS_SCALAR);

                    using operating_curve_type = typename crypto3::algebra::curves::pallas;
                    using operating_field_type = operating_curve_type::base_field_type;

                    if (std::is_same<BlueprintFieldType, operating_field_type>::value) {
                        using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                        using component_type = components::curve_element_decomposed_variable_base_scalar_mul<
                                ArithmetizationType, operating_curve_type, 15>;
                        typename component_type::result_type res = 
                            detail::handle_native_curve_non_native_scalar_multiplication_component<BlueprintFieldType, ArithmetizationParams, operating_curve_type>(
                                operand_curve, operand_field, frame.vectors, bp, assignment, start_row);
                        std::vector<crypto3::zk::snark::plonk_variable<BlueprintFieldType>> res_vector = {res.X, res.Y};
                        frame.vectors[inst] = res_vector;
                    } else {
                        assert(1==0 && "non-native pallas multiplication is not implemented");
                    }

                    break;
                }

                case llvm::ELLIPTIC_CURVE_CURVE25519: {
                    assert(llvm::cast<llvm::GaloisFieldType>(op_field_type)->getFieldKind() == llvm::GALOIS_FIELD_CURVE25519_SCALAR);

                    using operating_field_type = typename crypto3::algebra::curves::ed25519::base_field_type;

                    if (std::is_same<BlueprintFieldType, operating_field_type>::value) {
                        assert(1==0 && "native curve25519 multiplication is not implemented");
                    } else {
                        assert(1==0 && "non-native curve25519 multiplication is not implemented");

                    }

                    break;
                }

                case llvm::ELLIPTIC_CURVE_BLS12381: {
                    assert(llvm::cast<llvm::GaloisFieldType>(op_field_type)->getFieldKind() == llvm::GALOIS_FIELD_BLS12381_SCALAR);

                    using operating_field_type = typename crypto3::algebra::curves::bls12<381>::base_field_type;

                    if (std::is_same<BlueprintFieldType, operating_field_type>::value) {
                        assert(1==0 && "native bls12381 multiplication is not implemented");
                    } else {
                        assert(1==0 && "non-native bls12381 multiplication is not implemented");
                    }

                    break;
                }

                default:
                    assert(1 == 0 && "unsupported field operand type");
            };
        }

    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_CURVE_MULTIPLICATION_HPP
