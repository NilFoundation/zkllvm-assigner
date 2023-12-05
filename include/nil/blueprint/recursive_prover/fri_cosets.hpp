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

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/components/systems/snark/plonk/placeholder/fri_cosets.hpp>

#include <nil/blueprint/asserts.hpp>
#include <nil/blueprint/stack.hpp>
#include <nil/blueprint/non_native_marshalling.hpp>
#include <nil/blueprint/policy/policy_manager.hpp>
#include <nil/blueprint/extract_constructor_parameters.hpp>

namespace nil {
    namespace blueprint {
        namespace detail {

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        void handle_native_fri_cosets_component(
            llvm::Value *result_value,
            llvm::Value *result_length_value,
            llvm::Value *omega_value,
            llvm::Value *input,
            typename std::map<const llvm::Value *, std::vector<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>> &vectors,
            typename std::map<const llvm::Value *, crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &variables,
            program_memory<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &memory,
            circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
            assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
            std::uint32_t start_row) {

            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
            var component_input = variables[input];

            typename BlueprintFieldType::value_type omega = extract_constant_field_value<BlueprintFieldType>(omega_value);
            std::size_t res_length = extract_constant_size_t_value<BlueprintFieldType>(result_length_value);

            using component_type = components::fri_cosets<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, BlueprintFieldType>;

            const auto p = PolicyManager::get_parameters(ManifestReader<component_type, ArithmetizationParams>::get_witness(0, res_length));
            component_type component_instance =  component_type(p.witness,
                ManifestReader<component_type, ArithmetizationParams>::get_constants(), ManifestReader<component_type,
                    ArithmetizationParams>::get_public_inputs(), res_length, omega);

            components::generate_circuit(component_instance, bp, assignment, {component_input}, start_row);
            std::vector<std::array<var, 3>> result = components::generate_assignments(component_instance, assignment, {component_input}, start_row).output;

            ptr_type result_ptr = static_cast<ptr_type>(
                typename BlueprintFieldType::integral_type(var_value(assignment, variables[result_value]).data));
            for(std::size_t i = 0; i < result.size(); i++) {
                for(std::size_t j = 0; j < 3; j++) {
                    ASSERT(memory[result_ptr].size == (BlueprintFieldType::number_bits + 7) / 8);
                    memory.store(result_ptr++, result[i][j]);
                }
            }
        }

        }    // namespace detail

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        void handle_fri_cosets_component(
            const llvm::Instruction *inst,
            stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
            program_memory<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &memory,
            circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
            assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
            std::uint32_t start_row) {

            llvm::Value *result_value = inst->getOperand(0);
            llvm::Value *result_length_value = inst->getOperand(1);
            llvm::Value *omega_value = inst->getOperand(2);
            llvm::Value *input = inst->getOperand(3);

            detail::handle_native_fri_cosets_component<BlueprintFieldType, ArithmetizationParams>(
                result_value, result_length_value, omega_value, input, frame.vectors, frame.scalars, memory, bp, assignment, start_row);

        }

    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_RECURSIVE_PROVER_FRI_COSETS_HPP
