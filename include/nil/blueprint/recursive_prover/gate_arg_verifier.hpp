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

#ifndef CRYPTO3_ASSIGNER_RECURSIVE_PROVER_GATE_ARG_VERIFIER_HPP
#define CRYPTO3_ASSIGNER_RECURSIVE_PROVER_GATE_ARG_VERIFIER_HPP

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
            typename components::basic_constraints_verifier<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>::result_type
            handle_native_gate_arg_verifier_component(
                llvm::Value *selectors_value,
                llvm::Value *gates_sizes_value,
                llvm::Value *gates_amount_value,
                llvm::Value *constraints_value,
                llvm::Value *constraints_amount_value,
                llvm::Value *theta_value,
                typename std::map<const llvm::Value *, crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &variables,
                program_memory<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &memory,
                circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                component_calls &statistics,
                const common_component_parameters& param) {

                using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
                var theta = variables[theta_value];

                std::size_t gates_amount = extract_constant_size_t_value<BlueprintFieldType>(gates_amount_value);

                std::size_t constraints_amount = extract_constant_size_t_value<BlueprintFieldType>(constraints_amount_value);

                std::vector<std::size_t> gates_sizes =
                    extract_constant_vector<BlueprintFieldType>(gates_sizes_value);

                ASSERT(gates_sizes.size() == gates_amount);

                size_t gates_sizes_sum = 0;
                for(std::size_t i = 0; i < gates_sizes.size(); i++) {
                    gates_sizes_sum += gates_sizes[i];
                }

                if (gates_sizes_sum != constraints_amount) {
                    std::cerr << "constraints amount: " << constraints_amount << "\n";
                    std::cerr << "gates sizes: ";
                    for (std::size_t gs : gates_sizes) {
                        std::cerr << gs << " ";
                    }
                    std::cerr << "sum is " << gates_sizes_sum << std::endl;
                    UNREACHABLE("constraints amount is not equal to the sum of the gates sizes");
                }


                std::vector<var> selectors = extract_intrinsic_input_vector<BlueprintFieldType, var>(
                    selectors_value, gates_amount, variables, memory, assignment, param.gen_mode);

                std::vector<var> constraints = extract_intrinsic_input_vector<BlueprintFieldType, var>(
                    constraints_value, constraints_amount, variables, memory, assignment, param.gen_mode);

                using component_type = components::basic_constraints_verifier<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

                typename component_type::input_type instance_input = {theta, constraints, selectors};

                return get_component_result<BlueprintFieldType, component_type>
                    (bp, assignment, statistics, param, instance_input, gates_sizes);

            }

        }    // namespace detail

        template<typename BlueprintFieldType>
        void handle_gate_arg_verifier_component(
            const llvm::Instruction *inst,
            stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
            program_memory<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &memory,
            circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                &assignment,
            component_calls &statistics,
            const common_component_parameters& param) {

            llvm::Value *selectors_value = inst->getOperand(0);
            llvm::Value *gates_sizes_value = inst->getOperand(1);
            llvm::Value *gates_amount_value = inst->getOperand(2);
            llvm::Value *constraints_value = inst->getOperand(3);
            llvm::Value *constraints_amount_value = inst->getOperand(4);
            llvm::Value *theta_value = inst->getOperand(5);

            using component_type = components::basic_constraints_verifier<
            crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

            const auto& res = detail::handle_native_gate_arg_verifier_component<BlueprintFieldType>(
                    selectors_value, gates_sizes_value, gates_amount_value, constraints_value, constraints_amount_value, theta_value,
                    frame.scalars, memory, bp, assignment, statistics, param);
            handle_component_result<BlueprintFieldType, component_type>(assignment, inst, frame, res, param.gen_mode);
        }
    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_RECURSIVE_PROVER_GATE_ARG_VERIFIER_HPP
