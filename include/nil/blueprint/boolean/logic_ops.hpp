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

#ifndef CRYPTO3_ASSIGNER_LOGIC_OPS_HPP
#define CRYPTO3_ASSIGNER_LOGIC_OPS_HPP

#include "llvm/IR/Type.h"
#include "llvm/IR/TypeFinder.h"
#include "llvm/IR/TypedPointerType.h"

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/logic_ops.hpp>

#include <nil/blueprint/asserts.hpp>
#include <nil/blueprint/stack.hpp>

namespace nil {
    namespace blueprint {

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        typename crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>
            handle_logic_and(
                const typename crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type> &x,
                const typename crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type> &y,
                circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                std::uint32_t start_row,
                std::size_t &public_input_idx) {

            std::array<std::uint32_t, 2 + 1> witnesses;
            for (std::uint32_t i = 0; i < 2 + 1; i++) {
                witnesses[i] = i;
            }
            using arithmetization_type = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
            components::logic_and<arithmetization_type> component_instance(witnesses);

            typename components::logic_and<arithmetization_type>::input_type instance_input;
            instance_input.input[0] = x;
            instance_input.input[1] = y;

            components::generate_circuit(component_instance, bp, assignment, instance_input, start_row);
            return components::generate_assignments(component_instance, assignment, instance_input, start_row).output;
        }

    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_LOGIC_OPS_HPP
