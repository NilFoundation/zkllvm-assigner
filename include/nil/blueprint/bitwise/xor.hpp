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

#ifndef ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_BITWISE_XOR_HPP_
#define ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_BITWISE_XOR_HPP_

#include "llvm/IR/Type.h"
#include "llvm/IR/TypeFinder.h"
#include "llvm/IR/TypedPointerType.h"

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/asserts.hpp>
#include <nil/blueprint/stack.hpp>

namespace nil {
    namespace blueprint {

        template<typename BlueprintFieldType>
        void handle_scalar_bitwise_xor_component(
                const llvm::Instruction *inst,
                stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
                circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                column_type<BlueprintFieldType> &internal_storage,
                component_calls &statistics,
                const common_component_parameters& param) {

                using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

                var x = frame.scalars[inst->getOperand(0)];
                var y = frame.scalars[inst->getOperand(1)];

                using component_type = components::logic_xor<
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

                typename component_type::input_type instance_input;
                instance_input.input[0] = x;
                instance_input.input[1] = y;

                handle_component<BlueprintFieldType, component_type>
                    (bp, assignment, internal_storage, statistics, param, instance_input, inst, frame);
        }

    }    // namespace blueprint
}    // namespace nil

#endif    // ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_BITWISE_XOR_HPP_
