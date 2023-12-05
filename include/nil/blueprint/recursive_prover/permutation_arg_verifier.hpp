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

#ifndef CRYPTO3_ASSIGNER_RECURSIVE_PROVER_PERMUTATION_ARG_VERIFIER_HPP
#define CRYPTO3_ASSIGNER_RECURSIVE_PROVER_PERMUTATION_ARG_VERIFIER_HPP

#include "llvm/IR/Type.h"
#include "llvm/IR/TypeFinder.h"
#include "llvm/IR/TypedPointerType.h"

#include <nil/blueprint/non_native_marshalling.hpp>
#include <nil/blueprint/extract_constructor_parameters.hpp>
#include <nil/blueprint/handle_component.hpp>

namespace nil {
    namespace blueprint {
        namespace detail {

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename components::permutation_verifier<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>::result_type
            handle_native_permutation_arg_verifier_component(
                llvm::Value *f_value,
                llvm::Value *Se_value,
                llvm::Value *Ssigma_value,
                llvm::Value *input_length_value,
                llvm::Value *L0_value,
                llvm::Value *V_value,
                llvm::Value *V_zeta_value,
                llvm::Value *q_last_value,
                llvm::Value *q_pad_value,
                llvm::Value *thetas_value,
                typename std::map<const llvm::Value *, std::vector<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>> &vectors,
                typename std::map<const llvm::Value *, crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &variables,
                program_memory<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &memory,
                circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                std::uint32_t start_row) {

                using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
                var L0 = variables[L0_value];
                var V = variables[V_value];
                var V_zeta = variables[V_zeta_value];
                var q_last = variables[q_last_value];
                var q_pad = variables[q_pad_value];
                ASSERT(vectors[thetas_value].size() == 2);
                std::array<var, 2> thetas = {vectors[thetas_value][0], vectors[thetas_value][1]};

                std::size_t input_length = extract_constant_size_t_value<BlueprintFieldType>(input_length_value);

                std::vector<var> Ssigma = extract_intrinsic_input_vector<BlueprintFieldType, ArithmetizationParams, var>(
                    Ssigma_value, input_length, variables, memory, assignment);

                std::vector<var> f = extract_intrinsic_input_vector<BlueprintFieldType, ArithmetizationParams, var>(
                    f_value, input_length, variables, memory, assignment);

                std::vector<var> Se = extract_intrinsic_input_vector<BlueprintFieldType, ArithmetizationParams, var>(
                    Se_value, input_length, variables, memory, assignment);


                using component_type = components::permutation_verifier<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>;

                typename component_type::input_type instance_input = {
                    f,
                    Se,
                    Ssigma,
                    L0,
                    V,
                    V_zeta,
                    q_last,
                    q_pad,
                    thetas
                    };

                return get_component_result<BlueprintFieldType, ArithmetizationParams, component_type>
                    (bp, assignment, start_row, instance_input, input_length);

            }

        }    // namespace detail

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        void handle_permutation_arg_verifier_component(
            const llvm::Instruction *inst,
            stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
            program_memory<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &memory,
            circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
            std::uint32_t start_row, bool next_prover) {

            llvm::Value *f_value = inst->getOperand(0);
            llvm::Value *Se_value = inst->getOperand(1);
            llvm::Value *Ssigma_value = inst->getOperand(2);
            llvm::Value *input_length_value = inst->getOperand(3);
            llvm::Value *L0_value = inst->getOperand(4);
            llvm::Value *V_value = inst->getOperand(5);
            llvm::Value *V_zeta_value = inst->getOperand(6);
            llvm::Value *q_last_value = inst->getOperand(7);
            llvm::Value *q_pad_value = inst->getOperand(8);
            llvm::Value *thetas_value = inst->getOperand(9);

            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

            using component_type = components::permutation_verifier<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>;


            typename component_type::result_type res = detail::handle_native_permutation_arg_verifier_component<BlueprintFieldType, ArithmetizationParams>(
                f_value, Se_value, Ssigma_value, input_length_value, L0_value,
                    V_value, V_zeta_value, q_last_value, q_pad_value, thetas_value,
                        frame.vectors, frame.scalars, memory, bp, assignment, start_row);

            handle_component_result<BlueprintFieldType, ArithmetizationParams, component_type>(assignment, inst, frame, next_prover, res);

        }
    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_RECURSIVE_PROVER_PERMUTATION_ARG_VERIFIER_HPP
