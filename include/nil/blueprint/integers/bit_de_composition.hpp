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

#ifndef CRYPTO3_ASSIGNER_INTEGER_BIT_DE_COMPOSITION_HPP
#define CRYPTO3_ASSIGNER_INTEGER_BIT_DE_COMPOSITION_HPP

#include "llvm/IR/Type.h"
#include "llvm/IR/TypeFinder.h"
#include "llvm/IR/TypedPointerType.h"

#include <nil/blueprint/non_native_marshalling.hpp>
#include <nil/blueprint/handle_component.hpp>
#include <nil/blueprint/extract_constructor_parameters.hpp>

namespace nil {
    namespace blueprint {
        namespace detail {

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        void handle_native_field_decomposition_component(
            std::size_t BitsAmount,
            llvm::Value *result_value,
            llvm::Value *input,
            bool is_msb,
            typename std::map<const llvm::Value *, std::vector<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>> &vectors,
            typename std::map<const llvm::Value *, crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &variables,
            program_memory<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &memory,
            circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
            component_calls &statistics,
            const common_component_parameters& param) {

            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
            var component_input = variables[input];

            using mode = nil::blueprint::components::bit_composition_mode;
            mode Mode = is_msb ? mode::MSB : mode::LSB;

            using component_type = nil::blueprint::components::bit_decomposition<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>;
            typename component_type::input_type instance_input({component_input});

            auto result = get_component_result<BlueprintFieldType, ArithmetizationParams, component_type>
                (bp, assignment, statistics, param, instance_input, BitsAmount, Mode).output;

            if (std::uint8_t(param.gen_mode & generation_mode::ASSIGNMENTS)) {
                ptr_type result_ptr = static_cast<ptr_type>(
                    typename BlueprintFieldType::integral_type(var_value(assignment, variables[result_value]).data));
                for (var v : result) {
                    ASSERT(memory[result_ptr].size == (BlueprintFieldType::number_bits + 7) / 8);
                    memory.store(result_ptr++, v);
                }
            }
        }

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        typename components::bit_composition<
        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>::result_type
            handle_native_field_bit_composition_component(
            llvm::Value *input_value,
            llvm::Value *bitness_value,
            llvm::Value *operand_sig_bit,
            typename std::map<const llvm::Value *, std::vector<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>> &vectors,
            typename std::map<const llvm::Value *, crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &variables,
            program_memory<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &memory,
            circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
            component_calls &statistics,
            const common_component_parameters& param) {

            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

            using component_type = nil::blueprint::components::bit_composition<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>;

            bool is_msb = extract_constant_bool_value<BlueprintFieldType>(operand_sig_bit);
            using mode = nil::blueprint::components::bit_composition_mode;
            mode Mode = is_msb ? mode::MSB : mode::LSB;

            std::size_t bitness_from_intrinsic = extract_constant_size_t_value<BlueprintFieldType>(bitness_value);

            std::vector<var> component_input = extract_intrinsic_input_vector<BlueprintFieldType, ArithmetizationParams, var>(
                    input_value, bitness_from_intrinsic, variables, memory, assignment, param.gen_mode);
            typename component_type::input_type instance_input({component_input});

            return get_component_result<BlueprintFieldType, ArithmetizationParams, component_type>
                (bp, assignment, statistics, param, instance_input, bitness_from_intrinsic, true, Mode);
            }
        }    // namespace detail

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        void handle_integer_bit_decomposition_component(
            const llvm::Instruction *inst,
            stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
            program_memory<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &memory,
            circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
            component_calls &statistics,
            const common_component_parameters& param) {

            llvm::Value *result_value = inst->getOperand(0);
            llvm::Value *bitness_value = inst->getOperand(1);
            llvm::Value *input = inst->getOperand(2);
            llvm::Value *operand_sig_bit = inst->getOperand(3);

            std::size_t bitness_from_intrinsic = nil::blueprint::detail::extract_constant_size_t_value<BlueprintFieldType>(bitness_value);

            auto sig_bit_marshalled = marshal_field_val<BlueprintFieldType>(operand_sig_bit);
            ASSERT(sig_bit_marshalled.size() == 1);
            bool is_msb =
                static_cast<bool>(typename BlueprintFieldType::integral_type(sig_bit_marshalled[0].data));

            detail::handle_native_field_decomposition_component<BlueprintFieldType, ArithmetizationParams>(
                                bitness_from_intrinsic, result_value, input, is_msb, frame.vectors,
                                frame.scalars, memory, bp, assignment, statistics, param);
        }

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        void handle_integer_bit_composition_component(
            const llvm::Instruction *inst,
            stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
            program_memory<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &memory,
            circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
            component_calls &statistics,
            const common_component_parameters& param) {

            using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;
            using component_type = nil::blueprint::components::bit_composition<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>;

            llvm::Value *result_value = inst->getOperand(0);
            llvm::Value *bitness_value = inst->getOperand(1);
            llvm::Value *operand_sig_bit = inst->getOperand(2);

            const auto res = detail::handle_native_field_bit_composition_component<BlueprintFieldType, ArithmetizationParams>(
                                result_value, bitness_value, operand_sig_bit, frame.vectors,
                                frame.scalars, memory,  bp, assignment, statistics, param);

            handle_component_result<BlueprintFieldType, ArithmetizationParams, component_type>(assignment, inst, frame, res, param.gen_mode);
        }

    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_INTEGER_BIT_DE_COMPOSITION_HPP
