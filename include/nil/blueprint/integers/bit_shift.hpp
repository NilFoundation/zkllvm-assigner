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

#ifndef ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_INTEGERS_BIT_SHIFT_HPP_
#define ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_INTEGERS_BIT_SHIFT_HPP_

#include "llvm/IR/Type.h"
#include "llvm/IR/TypeFinder.h"
#include "llvm/IR/TypedPointerType.h"

#include <nil/blueprint/handle_component.hpp>


namespace nil {
    namespace blueprint {
        namespace detail {

        template<typename BlueprintFieldType>
        typename components::bit_shift_constant<
        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>::result_type
            handle_native_field_bit_shift_constant_component(
            std::size_t Bitness,
            llvm::Value *operand0, llvm::Value *operand1,
            typename std::map<const llvm::Value *, crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &variables,
            circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                &assignment,
            column_type<BlueprintFieldType> &internal_storage,
            component_calls &statistics,
            const common_component_parameters& param,
            typename nil::blueprint::components::bit_shift_mode left_or_right) {

            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

            var x = variables[operand0];
            var shift_var = variables[operand1];

            //TODO: Shift should be input of the component, not as done there
            //for now Shift must be constant
            ASSERT(shift_var.type == var::column_type::constant && assignment.constant(shift_var.index).size() > shift_var.rotation);
            std::size_t Shift = std::size_t(typename BlueprintFieldType::integral_type(var_value(assignment, shift_var).data));

            using component_type = nil::blueprint::components::bit_shift_constant<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;
            typename component_type::input_type instance_input({x});

            using nil::blueprint::components::bit_shift_mode;

            return get_component_result<BlueprintFieldType, component_type>
                (bp, assignment, internal_storage, statistics, param, instance_input, Bitness, Shift, left_or_right);
            }
        }    // namespace detail

        template<typename BlueprintFieldType>
        void handle_integer_bit_shift_constant_component(
            const llvm::Instruction *inst,
            stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
            circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                &assignment,
            column_type<BlueprintFieldType> &internal_storage,
            component_calls &statistics,
            const common_component_parameters& param,
            typename nil::blueprint::components::bit_shift_mode left_or_right) {

            using component_type = nil::blueprint::components::bit_shift_constant<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

            llvm::Value *operand0 = inst->getOperand(0);
            llvm::Value *operand1 = inst->getOperand(1);

            ASSERT(inst->getOperand(0)->getType()->getPrimitiveSizeInBits() == inst->getOperand(1)->getType()->getPrimitiveSizeInBits());

            std::size_t bitness = inst->getOperand(0)->getType()->getPrimitiveSizeInBits();

            const auto res = detail::handle_native_field_bit_shift_constant_component<BlueprintFieldType>(
                                bitness, operand0, operand1, frame.scalars, bp, assignment, internal_storage, statistics, param, left_or_right);
            handle_component_result<BlueprintFieldType, component_type>(assignment, inst, frame, res, param.gen_mode);
        }

    }    // namespace blueprint
}    // namespace nil

#endif    // ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_INTEGERS_BIT_SHIFT_HPP_
