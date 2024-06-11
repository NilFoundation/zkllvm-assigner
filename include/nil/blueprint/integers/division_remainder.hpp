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

#ifndef ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_INTEGERS_DIVISION_REMAINDER_HPP_
#define ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_INTEGERS_DIVISION_REMAINDER_HPP_

#include "llvm/IR/Type.h"
#include "llvm/IR/TypeFinder.h"
#include "llvm/IR/TypedPointerType.h"

#include <nil/blueprint/handle_component.hpp>

namespace nil {
    namespace blueprint {
        namespace detail {



        template<typename BlueprintFieldType>
        typename components::division_remainder<
        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>::result_type
            handle_native_field_division_remainder_component(
            std::size_t Bitness,
            llvm::Value *operand0, llvm::Value *operand1,
            typename std::map<const llvm::Value *, crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &variables,
            circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                &assignment,
            column_type<BlueprintFieldType> &internal_storage,
            component_handler_input_wrapper<BlueprintFieldType>& input_wrapper,
            const common_component_parameters& param) {

            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
            using component_type = components::division_remainder<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

            var x = variables[operand0];
            var y = variables[operand1];
            typename component_type::input_type instance_input({x, y});

            return get_component_result<BlueprintFieldType, component_type>
                (bp, assignment, internal_storage, input_wrapper, param, instance_input, Bitness, true);
            }
        }    // namespace detail

        template<typename BlueprintFieldType>
        void handle_integer_division_remainder_component(
            const llvm::Instruction *inst,
            stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
            circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                &assignment,
            column_type<BlueprintFieldType> &internal_storage,
            component_handler_input_wrapper<BlueprintFieldType>& input_wrapper,
            const common_component_parameters& param,
            bool is_division) {

            using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;

            llvm::Value *operand0 = inst->getOperand(0);
            llvm::Value *operand1 = inst->getOperand(1);

            ASSERT(inst->getOperand(0)->getType()->getPrimitiveSizeInBits() == inst->getOperand(1)->getType()->getPrimitiveSizeInBits());

            std::size_t bitness = inst->getOperand(0)->getType()->getPrimitiveSizeInBits();

            crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type> res;
            if (is_division) {
                res = detail::handle_native_field_division_remainder_component<BlueprintFieldType>(
                                bitness, operand0, operand1, frame.scalars, bp, assignment, internal_storage, input_wrapper, param).quotient;
            }
            else {
                res = detail::handle_native_field_division_remainder_component<BlueprintFieldType>(
                                bitness, operand0, operand1, frame.scalars, bp, assignment, internal_storage, input_wrapper, param).remainder;
            }
            handle_result<BlueprintFieldType>
                (assignment, inst, frame, {res}, param.gen_mode);
        }

    }    // namespace blueprint
}    // namespace nil

#endif    // ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_INTEGERS_DIVISION_REMAINDER_HPP_
