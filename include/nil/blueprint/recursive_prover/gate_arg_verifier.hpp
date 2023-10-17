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

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/components/systems/snark/plonk/placeholder/gate_argument_verifier.hpp>

#include <nil/blueprint/asserts.hpp>
#include <nil/blueprint/stack.hpp>
#include <nil/blueprint/non_native_marshalling.hpp>
#include <nil/blueprint/policy/policy_manager.hpp>

namespace nil {
    namespace blueprint {
        namespace detail {

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename components::basic_constraints_verifier<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>::result_type
            handle_native_gate_arg_verifier_component(
                llvm::Value *selectors_value,
                llvm::Value *gates_sizes_value,
                llvm::Value *gates_amount_value,
                llvm::Value *constraints_value,
                llvm::Value *constraints_amount_value,
                llvm::Value *theta_value,
                typename std::map<const llvm::Value *, std::vector<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>> &vectors,
                typename std::map<const llvm::Value *, crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &variables,
                program_memory<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &memory,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                std::uint32_t start_row) {

                using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
                var theta = variables[theta_value];

                auto marshalling_vector_gates_amount = marshal_field_val<BlueprintFieldType>(gates_amount_value);
                ASSERT(marshalling_vector_gates_amount.size() == 1);
                std::size_t gates_amount = std::size_t(typename BlueprintFieldType::integral_type(marshalling_vector_gates_amount[0].data));

                auto marshalling_vector_constraints_amount = marshal_field_val<BlueprintFieldType>(constraints_amount_value);
                ASSERT(marshalling_vector_constraints_amount.size() == 1);
                std::size_t constraints_amount = std::size_t(typename BlueprintFieldType::integral_type(marshalling_vector_constraints_amount[0].data));

                size_t gates_sizes_sum = 0;
                std::vector<std::size_t> gates_sizes = std::vector<std::size_t>(gates_amount);

                ASSERT(gates_sizes_value->getType()->isPointerTy());
                ASSERT(llvm::isa<llvm::GlobalValue>(gates_sizes_value));
                auto gv = llvm::cast<llvm::GlobalVariable>(gates_sizes_value);
                auto struct_constant = gv->getInitializer();
                ASSERT(struct_constant->getType()->getStructNumElements() == 1);
                auto array_constant = struct_constant->getAggregateElement(0u);
                ASSERT(array_constant->getType()->isArrayTy());
                for (unsigned i = 0; i < array_constant->getType()->getArrayNumElements(); ++i) {
                    auto elem_constant = array_constant->getAggregateElement(i);
                    auto marshalling_output_vector = marshal_field_val<BlueprintFieldType>(elem_constant);
                    ASSERT(marshalling_output_vector.size() == 1);
                    gates_sizes[i] = (std::size_t)typename BlueprintFieldType::integral_type(marshalling_output_vector[0].data);
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


                std::vector<var> selectors;
                ptr_type selectors_ptr = static_cast<ptr_type>(
                    typename BlueprintFieldType::integral_type(var_value(assignment, variables[selectors_value]).data));
                for(std::size_t i = 0; i < gates_amount; i++) {
                        ASSERT(memory[selectors_ptr].size == (BlueprintFieldType::number_bits + 7) / 8);
                        selectors.push_back(memory.load(selectors_ptr++));
                }

                std::vector<var> constraints;
                ptr_type constraints_ptr = static_cast<ptr_type>(
                    typename BlueprintFieldType::integral_type(var_value(assignment, variables[constraints_value]).data));
                for(std::size_t i = 0; i < constraints_amount; i++) {
                        ASSERT(memory[constraints_ptr].size == (BlueprintFieldType::number_bits + 7) / 8);
                        constraints.push_back(memory.load(constraints_ptr++));
                }


                using component_type = components::basic_constraints_verifier<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>;

                const auto p = PolicyManager::get_parameters(ManifestReader<component_type, ArithmetizationParams>::get_witness(0, gates_sizes));
                component_type component_instance =  component_type(p.witness,
                    ManifestReader<component_type, ArithmetizationParams>::get_constants(),
                    ManifestReader<component_type,ArithmetizationParams>::get_public_inputs(),
                    gates_sizes);


                typename component_type::input_type instance_input = {theta, constraints, selectors};


                components::generate_circuit(component_instance, bp, assignment, instance_input, start_row);
                return components::generate_assignments(component_instance, assignment, instance_input, start_row);

            }

        }    // namespace detail

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        void handle_gate_arg_verifier_component(
            const llvm::Instruction *inst,
            stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
            program_memory<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &memory,
            circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
            assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
            std::uint32_t start_row) {

            llvm::Value *selectors_value = inst->getOperand(0);
            llvm::Value *gates_sizes_value = inst->getOperand(1);
            llvm::Value *gates_amount_value = inst->getOperand(2);
            llvm::Value *constraints_value = inst->getOperand(3);
            llvm::Value *constraints_amount_value = inst->getOperand(4);
            llvm::Value *theta_value = inst->getOperand(5);

            frame.scalars[inst] = detail::handle_native_gate_arg_verifier_component<BlueprintFieldType, ArithmetizationParams>(
                selectors_value, gates_sizes_value, gates_amount_value, constraints_value, constraints_amount_value, theta_value,
                    frame.vectors, frame.scalars, memory, bp, assignment, start_row).output;

        }
    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_RECURSIVE_PROVER_GATE_ARG_VERIFIER_HPP
