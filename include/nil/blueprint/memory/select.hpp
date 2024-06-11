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

#ifndef ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_SELECT_HPP_
#define ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_SELECT_HPP_

#include "llvm/IR/Type.h"
#include "llvm/IR/TypeFinder.h"
#include "llvm/IR/TypedPointerType.h"

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/asserts.hpp>
#include <nil/blueprint/stack.hpp>

#include <nil/blueprint/handle_component.hpp>

namespace nil {
    namespace blueprint {

        template<typename BlueprintFieldType, typename var>
            var create_select_component(
                var condition, var true_var, var false_var,
                circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                column_type<BlueprintFieldType> &internal_storage,
                component_handler_input_wrapper<BlueprintFieldType>& input_wrapper,
                const common_component_parameters& param,
                crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type> one_var
            ) {
                using arithmetization_type = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;

                using div_or_zero_comp_type = components::division_or_zero<arithmetization_type, BlueprintFieldType>;
                using field_mul_comp_type = components::multiplication<arithmetization_type, BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;
                using field_sub_comp_type = components::subtraction<arithmetization_type, BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;
                using field_add_comp_type = components::addition<arithmetization_type, BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

                typename div_or_zero_comp_type::input_type div_or_zero_input({condition, condition});
                var condition_0_or_1 = get_component_result<BlueprintFieldType, div_or_zero_comp_type>
                    (bp, assignment, internal_storage, input_wrapper, param, div_or_zero_input).output; // returns 1 if !=0 and 0 if ==0

                typename field_mul_comp_type::input_type field_mul_input(condition_0_or_1, true_var);
                var contitioned_true_var = get_component_result<BlueprintFieldType, field_mul_comp_type>
                    (bp, assignment, internal_storage, input_wrapper, param, field_mul_input).output; // true_var if true, 0 if false

                typename field_sub_comp_type::input_type field_sub_input({one_var, condition_0_or_1});
                var inversed_condition_0_or_1 = get_component_result<BlueprintFieldType, field_sub_comp_type>
                    (bp, assignment, internal_storage, input_wrapper, param, field_sub_input).output; // true_var if true, 0 if false

                typename field_mul_comp_type::input_type field_mul_input_2(inversed_condition_0_or_1, false_var);
                var contitioned_false_var = get_component_result<BlueprintFieldType, field_mul_comp_type>
                    (bp, assignment, internal_storage, input_wrapper, param, field_mul_input_2).output; // false_var if false, 0 otherwise

                typename field_add_comp_type::input_type field_add_input({contitioned_true_var, contitioned_false_var});
                var result = get_component_result<BlueprintFieldType, field_add_comp_type>
                    (bp, assignment, internal_storage, input_wrapper, param, field_add_input).output; // true_var if true, false_var if false

                return result;
        }

        template<typename BlueprintFieldType>
            void handle_select_component(
                const llvm::Instruction *inst,
                stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
                circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                column_type<BlueprintFieldType> &internal_storage,
                component_handler_input_wrapper<BlueprintFieldType>& input_wrapper,
                const common_component_parameters& param,
                crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type> one_var) {

                using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
                using arithmetization_type = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
                using field_add_comp_type = components::addition<arithmetization_type, BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

                auto condition = frame.scalars[inst->getOperand(0)];
                auto true_var = frame.scalars[inst->getOperand(1)];
                auto false_var= frame.scalars[inst->getOperand(2)];

                var result = create_select_component<BlueprintFieldType, var>(
                                    condition, true_var, false_var, bp, assignment, internal_storage, input_wrapper, param, one_var);

                handle_result<BlueprintFieldType>(assignment, inst, frame, {result}, param.gen_mode);
        }

    }    // namespace blueprint
}    // namespace nil

#endif    // ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_SELECT_HPP_
