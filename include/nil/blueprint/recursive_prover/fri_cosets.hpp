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

#ifndef CRYPTO3_ASSIGNER_RECURSIVE_PROVER_FRI_COSETS_HPP
#define CRYPTO3_ASSIGNER_RECURSIVE_PROVER_FRI_COSETS_HPP

#include "llvm/IR/Type.h"
#include "llvm/IR/TypeFinder.h"
#include "llvm/IR/TypedPointerType.h"


#include <nil/blueprint/non_native_marshalling.hpp>
#include <nil/blueprint/extract_constructor_parameters.hpp>
#include <nil/blueprint/handle_component.hpp>

namespace nil {
    namespace blueprint {
        namespace detail {

        template<typename BlueprintFieldType>
        void handle_native_fri_cosets_component(
            llvm::Value *result_value,
            llvm::Value *result_length_value,
            llvm::Value *omega_value,
            llvm::Value *input,
            typename std::map<const llvm::Value *, std::vector<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>> &vectors,
            typename std::map<const llvm::Value *, crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &variables,
            program_memory<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &memory,
            circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                &assignment,
            column_type<BlueprintFieldType> &internal_storage,
            component_calls &statistics,
            const common_component_parameters& param) {

            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
            var component_input = variables[input];

            typename BlueprintFieldType::value_type omega = extract_constant_field_value<BlueprintFieldType>(omega_value);
            std::size_t res_length = extract_constant_size_t_value<BlueprintFieldType>(result_length_value);

            using component_type = components::fri_cosets<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>;
            typename component_type::input_type instance_input({component_input});

            const auto& result = get_component_result<BlueprintFieldType, component_type>
                (bp, assignment, internal_storage, statistics, param, instance_input, res_length, omega).output;

            if (param.gen_mode.has_assignments()) {
                ptr_type result_ptr = static_cast<ptr_type>(
                    typename BlueprintFieldType::integral_type(detail::var_value<BlueprintFieldType, var>
                        (variables[result_value], assignment, internal_storage, true).data));
                for (std::size_t i = 0; i < result.size(); i++) {
                    for (std::size_t j = 0; j < 3; j++) {
                        ASSERT(memory[result_ptr].size == (BlueprintFieldType::number_bits + 7) / 8);
                        memory.store(result_ptr++, result[i][j]);
                    }
                }
            }
        }

        }    // namespace detail

        template<typename BlueprintFieldType>
        void handle_fri_cosets_component(
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
            llvm::Value *result_length_value = inst->getOperand(1);
            llvm::Value *omega_value = inst->getOperand(2);
            llvm::Value *input = inst->getOperand(3);

            detail::handle_native_fri_cosets_component<BlueprintFieldType>(
                result_value, result_length_value, omega_value, input, frame.vectors, frame.scalars, memory, bp, assignment, internal_storage, statistics, param);

        }

    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_RECURSIVE_PROVER_FRI_COSETS_HPP
