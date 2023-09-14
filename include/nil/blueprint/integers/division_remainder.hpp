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

#ifndef CRYPTO3_ASSIGNER_INTEGER_DIVISION_REMAINDER_HPP
#define CRYPTO3_ASSIGNER_INTEGER_DIVISION_REMAINDER_HPP

#include "llvm/IR/Type.h"
#include "llvm/IR/TypeFinder.h"
#include "llvm/IR/TypedPointerType.h"

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/division_remainder.hpp>

#include <nil/blueprint/asserts.hpp>
#include <nil/blueprint/stack.hpp>
#include <nil/blueprint/policy/policy_manager.hpp>

namespace nil {
    namespace blueprint {
        namespace detail {



        template<typename BlueprintFieldType, typename ArithmetizationParams>
        typename components::division_remainder<
        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>::result_type
            handle_native_field_division_remainder_component(
            std::size_t Bitness,
            llvm::Value *operand0, llvm::Value *operand1,
            typename std::map<const llvm::Value *, crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &variables,
            circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
            assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
            std::uint32_t start_row) {

            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
            using component_type = components::division_remainder<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>;
            const auto p = PolicyManager::get_parameters(ManifestReader<component_type, ArithmetizationParams>::get_witness(0, Bitness, true));
            component_type component_instance(p.witness, ManifestReader<component_type, ArithmetizationParams>::get_constants(), ManifestReader<component_type, ArithmetizationParams>::get_public_inputs(), Bitness, true);

            var x = variables[operand0];
            var y = variables[operand1];

            components::generate_circuit(component_instance, bp, assignment, {x, y}, start_row);
            return components::generate_assignments(component_instance, assignment, {x, y}, start_row);

            }
        }    // namespace detail

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        void handle_integer_division_remainder_component(
            const llvm::Instruction *inst,
            stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
            circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
            assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
            std::uint32_t start_row,
            bool is_division) {

            using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;

            llvm::Value *operand0 = inst->getOperand(0);
            llvm::Value *operand1 = inst->getOperand(1);

            ASSERT(inst->getOperand(0)->getType()->getPrimitiveSizeInBits() == inst->getOperand(1)->getType()->getPrimitiveSizeInBits());

            std::size_t bitness = inst->getOperand(0)->getType()->getPrimitiveSizeInBits();

            if (is_division) {
                frame.scalars[inst] = detail::handle_native_field_division_remainder_component<BlueprintFieldType, ArithmetizationParams>(
                                bitness, operand0, operand1, frame.scalars, bp, assignment, start_row).quotient;
            }
            else {
                frame.scalars[inst] = detail::handle_native_field_division_remainder_component<BlueprintFieldType, ArithmetizationParams>(
                                bitness, operand0, operand1, frame.scalars, bp, assignment, start_row).remainder;
            }

        }

    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_INTEGER_DIVISION_REMAINDER_HPP
