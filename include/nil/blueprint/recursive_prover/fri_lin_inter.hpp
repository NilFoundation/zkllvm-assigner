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

#ifndef CRYPTO3_ASSIGNER_RECURSIVE_PROVER_FRI_LIN_INTER_HPP
#define CRYPTO3_ASSIGNER_RECURSIVE_PROVER_FRI_LIN_INTER_HPP

#include "llvm/IR/Type.h"
#include "llvm/IR/TypeFinder.h"
#include "llvm/IR/TypedPointerType.h"

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/components/systems/snark/plonk/placeholder/fri_lin_inter.hpp>

#include <nil/blueprint/asserts.hpp>
#include <nil/blueprint/stack.hpp>
#include <nil/blueprint/non_native_marshalling.hpp>
#include <nil/blueprint/policy/policy_manager.hpp>
#include <nil/blueprint/extract_constructor_parameters.hpp>

namespace nil {
    namespace blueprint {

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        void handle_fri_lin_inter_component(
            const llvm::Instruction *inst,
            stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
            program_memory<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &memory,
            circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
            assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
            std::uint32_t start_row) {

            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

            var s = frame.scalars[inst->getOperand(0)];
            var y0 = frame.scalars[inst->getOperand(1)];
            var y1 = frame.scalars[inst->getOperand(2)];
            var alpha = frame.scalars[inst->getOperand(3)];

            using component_type = components::fri_lin_inter<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, BlueprintFieldType>;


            const auto p = detail::PolicyManager::get_parameters(detail::ManifestReader<component_type, ArithmetizationParams>::get_witness(0));

            component_type component_instance(p.witness, detail::ManifestReader<component_type, ArithmetizationParams>::get_constants(),
                detail::ManifestReader<component_type, ArithmetizationParams>::get_public_inputs());


            // component_type component_instance({0, 1, 2, 3, 4}, {}, {});

            components::generate_circuit(component_instance, bp, assignment, {s, y0, y1, alpha}, start_row);
            frame.scalars[inst] = components::generate_assignments(component_instance, assignment, {s, y0, y1, alpha}, start_row).output;

        }

    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_RECURSIVE_PROVER_FRI_LIN_INTER_HPP
