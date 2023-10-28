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

#ifndef CRYPTO3_ASSIGNER_FRI_ARRAY_SWAP_HPP
#define CRYPTO3_ASSIGNER_FRI_ARRAY_SWAP_HPP

#include "llvm/IR/Type.h"
#include "llvm/IR/TypeFinder.h"
#include "llvm/IR/TypedPointerType.h"

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/components/systems/snark/plonk/placeholder/fri_array_swap.hpp>

#include <nil/blueprint/asserts.hpp>
#include <nil/blueprint/stack.hpp>
#include <nil/blueprint/non_native_marshalling.hpp>
#include <nil/blueprint/policy/policy_manager.hpp>
#include <nil/blueprint/extract_constructor_parameters.hpp>

namespace nil {
    namespace blueprint {

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        void handle_fri_array_swap_component(
            const llvm::Instruction *inst,
            stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
            program_memory<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &memory,
            circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
            assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
            std::uint32_t start_row) {

            llvm::Value *result_value = inst->getOperand(0);
            llvm::Value *array_size_value = inst->getOperand(1);
            llvm::Value *input_array_value = inst->getOperand(2);
            llvm::Value *input_bool_value = inst->getOperand(3);

            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

            std::size_t array_size = detail::extract_component_constructor_parameter_size_t<BlueprintFieldType>(array_size_value);


            std::vector<var> input_array = detail::extract_intrinsic_input_vector<BlueprintFieldType, ArithmetizationParams, var>(
                    input_array_value, array_size, frame.scalars, memory, assignment);

            var input_bool = frame.scalars[input_bool_value];

            using component_type = components::fri_array_swap<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, BlueprintFieldType>;

            const auto p = detail::PolicyManager::get_parameters(detail::ManifestReader<component_type, ArithmetizationParams>::get_witness(
                0,
                array_size / 2
            ));

            component_type component_instance =  component_type(p.witness,
                detail::ManifestReader<component_type, ArithmetizationParams>::get_constants(),
                detail::ManifestReader<component_type,ArithmetizationParams>::get_public_inputs(),
                array_size / 2
                );


            typename component_type::input_type instance_input = {
                input_bool,
                input_array
            };


            components::generate_circuit(component_instance, bp, assignment, instance_input, start_row);
            std::vector<var> res = components::generate_assignments(component_instance, assignment, instance_input, start_row).output;

            ptr_type result_ptr = static_cast<ptr_type>(
                typename BlueprintFieldType::integral_type(var_value(assignment, frame.scalars[result_value]).data));
            for(std::size_t i = 0; i < array_size; i++) {
                ASSERT(memory[result_ptr].size == (BlueprintFieldType::number_bits + 7) / 8);
                memory.store(result_ptr++, res[i]);
            }
        }
    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_FRI_ARRAY_SWAP_HPP
