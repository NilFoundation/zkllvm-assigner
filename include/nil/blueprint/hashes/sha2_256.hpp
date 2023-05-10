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

#ifndef CRYPTO3_ASSIGNER_HASHES_SHA2_256_HPP
#define CRYPTO3_ASSIGNER_HASHES_SHA2_256_HPP

#include "llvm/IR/Type.h"
#include "llvm/IR/TypeFinder.h"
#include "llvm/IR/TypedPointerType.h"

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/curves/curve25519.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/component.hpp>
#include <nil/blueprint/components/hashes/sha2/plonk/sha256.hpp>

#include <nil/blueprint/stack.hpp>

namespace nil {
    namespace blueprint {
        template<typename BlueprintFieldType, typename ArithmetizationParams>
        void handle_sha2_256_component(
            const llvm::Instruction *inst,
            stack_frame<crypto3::zk::snark::plonk_variable<BlueprintFieldType>> &frame,
            circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
            assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignmnt,
            std::uint32_t start_row) {

            using var = crypto3::zk::snark::plonk_variable<BlueprintFieldType>;
            using component_type = components::sha256<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, 9>;

            constexpr const std::int32_t block_size = 2;
            constexpr const std::int32_t input_blocks_amount = 2;

            auto &block_arg = frame.vectors[inst->getOperand(0)];
            std::array<var, input_blocks_amount * block_size> input_block_vars;
            std::copy(block_arg.begin(), block_arg.end(), input_block_vars.begin());

            typename component_type::input_type instance_input = {input_block_vars};

            component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8}, {0}, {});

            components::generate_circuit(component_instance, bp, assignmnt, instance_input, start_row);

            typename component_type::result_type component_result =
                components::generate_assignments(component_instance, assignmnt, instance_input, start_row);

            std::vector<var> output(component_result.output.begin(), component_result.output.end());
            frame.vectors[inst] = output;
        }
    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_HASHES_SHA2_256_HPP
