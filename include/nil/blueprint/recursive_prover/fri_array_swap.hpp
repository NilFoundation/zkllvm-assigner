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

#ifndef ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_RECURSIVE_PROVER_FRI_ARRAY_SWAP_HPP_
#define ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_RECURSIVE_PROVER_FRI_ARRAY_SWAP_HPP_

#include "llvm/IR/Type.h"
#include "llvm/IR/TypeFinder.h"
#include "llvm/IR/TypedPointerType.h"

#include <nil/blueprint/non_native_marshalling.hpp>
#include <nil/blueprint/extract_constructor_parameters.hpp>
#include <nil/blueprint/handle_component.hpp>

namespace nil {
    namespace blueprint {

        template<typename BlueprintFieldType>
        void handle_fri_array_swap_component(
            const llvm::Instruction *inst,
            stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
            program_memory<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &memory,
            circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                &assignment,
            column_type<BlueprintFieldType> &internal_storage,
            component_calls &statistics,
            const common_component_parameters& param) {

            llvm::Value *result_value = inst->getOperand(0);
            llvm::Value *array_size_value = inst->getOperand(1);
            llvm::Value *input_array_value = inst->getOperand(2);
            llvm::Value *input_bool_value = inst->getOperand(3);

            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

            std::size_t array_size = detail::extract_constant_size_t_value<BlueprintFieldType>(array_size_value);


            std::vector<var> input_array = detail::extract_intrinsic_input_vector<BlueprintFieldType, var>(
                    input_array_value, array_size, frame.scalars, memory, assignment, internal_storage, param.gen_mode);

            var input_bool = frame.scalars[input_bool_value];

            using component_type = components::fri_array_swap<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>;

            typename component_type::input_type instance_input = {
                input_bool,
                input_array
            };

            std::vector<var> res = get_component_result<BlueprintFieldType, component_type>
                    (bp, assignment, internal_storage, statistics, param, instance_input, array_size / 2).output;

            if (!param.gen_mode.has_false_assignments()) {
                ptr_type result_ptr = static_cast<ptr_type>(typename BlueprintFieldType::integral_type(
                    detail::var_value<BlueprintFieldType, var>
                    (frame.scalars[result_value], assignment, internal_storage, true).data));
                for (std::size_t i = 0; i < array_size; i++) {
                    ASSERT(memory[result_ptr].size == (BlueprintFieldType::number_bits + 7) / 8);
                    memory.store(result_ptr++, res[i]);
                }
            }
        }
    }    // namespace blueprint
}    // namespace nil

#endif    // ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_RECURSIVE_PROVER_FRI_ARRAY_SWAP_HPP_
