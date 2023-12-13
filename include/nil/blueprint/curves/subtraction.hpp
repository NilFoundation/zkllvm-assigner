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

#ifndef CRYPTO3_ASSIGNER_CURVE_SUBTRACTION_HPP
#define CRYPTO3_ASSIGNER_CURVE_SUBTRACTION_HPP

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

#include <nil/blueprint/asserts.hpp>
#include <nil/blueprint/stack.hpp>

namespace nil {
    namespace blueprint {
        namespace detail {
        }    // namespace detail

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        void handle_curve_subtraction_component(
            const llvm::Instruction *inst,
            stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
            circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
            std::uint32_t start_row) {

            using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;

            llvm::Value *operand0 = inst->getOperand(0);
            llvm::Value *operand1 = inst->getOperand(1);

            llvm::Type *op0_type = operand0->getType();
            llvm::Type *op1_type = operand1->getType();

            ASSERT(llvm::cast<llvm::EllipticCurveType>(op0_type)->getCurveKind() ==
                   llvm::cast<llvm::EllipticCurveType>(op1_type)->getCurveKind());

            switch (llvm::cast<llvm::EllipticCurveType>(op0_type)->getCurveKind()) {
                case llvm::ELLIPTIC_CURVE_PALLAS: {
                    using operating_field_type = typename crypto3::algebra::curves::pallas::base_field_type;

                    if (std::is_same<BlueprintFieldType, operating_field_type>::value) {
                        UNREACHABLE("native pallas subtraction is not implemented");
                    } else {
                        UNREACHABLE("non-native pallas subtraction is not implemented");
                    }

                    break;
                }

                case llvm::ELLIPTIC_CURVE_VESTA: {
                    using operating_field_type = typename crypto3::algebra::curves::vesta::base_field_type;

                    if (std::is_same<BlueprintFieldType, operating_field_type>::value) {
                        UNREACHABLE("native vesta subtraction is not implemented");
                    } else {
                        UNREACHABLE("non-native vesta subtraction is not implemented");
                    }

                    break;
                }

                case llvm::ELLIPTIC_CURVE_CURVE25519: {
                    using operating_field_type = typename crypto3::algebra::curves::curve25519::base_field_type;

                    if (std::is_same<BlueprintFieldType, operating_field_type>::value) {
                        UNREACHABLE("native curve25519 subtraction is not implemented");
                    } else {
                        UNREACHABLE("non-native curve25519 subtraction is not implemented");

                    }

                    break;
                }

                case llvm::ELLIPTIC_CURVE_BLS12381: {
                    using operating_field_type = typename crypto3::algebra::curves::bls12<381>::base_field_type;

                    if (std::is_same<BlueprintFieldType, operating_field_type>::value) {
                        UNREACHABLE("native bls12381 subtraction is not implemented");
                    } else {
                        UNREACHABLE("non-native bls12381 subtraction is not implemented");
                    }

                    break;
                }

                default:
                    UNREACHABLE("unsupported field operand type");
            };
        }

    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_CURVE_SUBTRACTION_HPP
