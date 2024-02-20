//---------------------------------------------------------------------------//
// Copyright (c) 2023 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ASSIGNER_COMPARISON_HPP
#define CRYPTO3_ASSIGNER_COMPARISON_HPP

#include "llvm/IR/Type.h"
#include "llvm/IR/TypeFinder.h"
#include "llvm/IR/TypedPointerType.h"

#include <nil/blueprint/components/algebra/fields/plonk/non_native/comparison_mode.hpp>

#include <nil/blueprint/handle_component.hpp>

namespace nil {
    namespace blueprint {

        template<typename BlueprintFieldType, typename ArithmetizationParams, typename ComponentType>
        typename ComponentType::result_type
        handle_comparison_component_eq_neq(
                llvm::CmpInst::Predicate p,
                const typename crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type> &x,
                const typename crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type> &y,
                std::size_t Bitness,
                circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                &assignment,
                component_calls &statistics,
                const common_component_parameters& param) {

            typename ComponentType::input_type instance_input({x, y});

            switch (p) {
                case llvm::CmpInst::ICMP_EQ: {
                    return get_component_result<BlueprintFieldType, ArithmetizationParams, ComponentType>
                            (bp, assignment, statistics, param, instance_input, false);
                    break;
                }
                case llvm::CmpInst::ICMP_NE:{
                    return get_component_result<BlueprintFieldType, ArithmetizationParams, ComponentType>
                            (bp, assignment, statistics, param, instance_input, true);
                    break;
                }
                default:
                    UNREACHABLE("Unsupported icmp predicate");
                    break;
            }
        }

        template<typename BlueprintFieldType, typename ArithmetizationParams, typename ComponentType>
        typename ComponentType::result_type
            handle_comparison_component_others(
                llvm::CmpInst::Predicate p,
                const typename crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type> &x,
                const typename crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type> &y,
                std::size_t Bitness,
                circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                &assignment,
                component_calls &statistics,
                const common_component_parameters& param) {


            typename ComponentType::input_type instance_input({x, y});

            nil::blueprint::components::comparison_mode Mode;

            switch (p) {
                case llvm::CmpInst::ICMP_SGE:
                case llvm::CmpInst::ICMP_UGE:
                    Mode = nil::blueprint::components::comparison_mode::GREATER_EQUAL;
                    break;
                case llvm::CmpInst::ICMP_SGT:
                case llvm::CmpInst::ICMP_UGT:
                    Mode = nil::blueprint::components::comparison_mode::GREATER_THAN;
                    break;
                case llvm::CmpInst::ICMP_SLE:
                case llvm::CmpInst::ICMP_ULE:
                    Mode = nil::blueprint::components::comparison_mode::LESS_EQUAL;
                    break;
                case llvm::CmpInst::ICMP_SLT:
                case llvm::CmpInst::ICMP_ULT:
                    Mode = nil::blueprint::components::comparison_mode::LESS_THAN;
                    break;
                default:
                    UNREACHABLE("Unsupported icmp predicate");
                    break;
            }

            return get_component_result<BlueprintFieldType, ArithmetizationParams, ComponentType>
                (bp, assignment, statistics, param, instance_input, Mode);

        }

        template<typename BlueprintFieldType, typename ArithmetizationParams>
            void handle_comparison_component(
                const llvm::Instruction *inst,
                stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
                llvm::CmpInst::Predicate p,
                circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                &assignment,
                component_calls &statistics,
                const common_component_parameters& param
            ) {

                using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

                const var &x = frame.scalars[inst->getOperand(0)];
                const var &y = frame.scalars[inst->getOperand(1)];

                std::size_t bitness = inst->getOperand(0)->getType()->getPrimitiveSizeInBits();


            switch (p) {
                case llvm::CmpInst::ICMP_EQ:
                case llvm::CmpInst::ICMP_NE: {
                    using eq_component_type = components::equality_flag<
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>;

                    const auto& component_result = handle_comparison_component_eq_neq<
                        BlueprintFieldType, ArithmetizationParams, eq_component_type>(
                            p, x, y, bitness, bp, assignment, statistics, param);

                    handle_component_result<BlueprintFieldType, ArithmetizationParams, eq_component_type>
                        (assignment, inst, frame, component_result, param.gen_mode);
                    break;
                }

                case llvm::CmpInst::ICMP_SGE:
                case llvm::CmpInst::ICMP_UGE:
                case llvm::CmpInst::ICMP_SGT:
                case llvm::CmpInst::ICMP_UGT:
                case llvm::CmpInst::ICMP_SLE:
                case llvm::CmpInst::ICMP_ULE:
                case llvm::CmpInst::ICMP_SLT:
                case llvm::CmpInst::ICMP_ULT: {
                    using comp_component_type = components::comparison<
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>;

                    const auto& component_result = handle_comparison_component_others<
                        BlueprintFieldType, ArithmetizationParams, comp_component_type>(
                            p, x, y, bitness, bp, assignment, statistics, param);

                    handle_component_result<BlueprintFieldType, ArithmetizationParams, comp_component_type>
                        (assignment, inst, frame, component_result, param.gen_mode);
                    break;
                }

                default:
                    UNREACHABLE("Unsupported icmp predicate");
                    break;
            }
        }

    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_COMPARISON_HPP
