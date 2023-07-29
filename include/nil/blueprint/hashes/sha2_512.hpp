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

#ifndef CRYPTO3_ASSIGNER_HASHES_SHA2_512_HPP
#define CRYPTO3_ASSIGNER_HASHES_SHA2_512_HPP

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
#include <nil/blueprint/components/hashes/sha2/plonk/sha512.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/reduction.hpp>

#include <nil/blueprint/stack.hpp>

namespace nil {
    namespace blueprint {
        template<typename BlueprintFieldType, typename ArithmetizationParams>
        void handle_sha2_512_component(
            const llvm::Instruction *inst,
            stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
            circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
            assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignmnt,
            std::uint32_t start_row) {

            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
            using sha2_512_component_type = components::sha512<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, 9>;

            constexpr const std::int32_t ec_point_size = 2*4;
            constexpr const std::int32_t input_size = 2*ec_point_size + 4;

            const auto &arg0 = frame.vectors[inst->getOperand(0)];
            std::array<var, input_size> input_vars;
            std::copy(arg0.begin(), arg0.end(), input_vars.begin());
            const auto &arg1 = frame.vectors[inst->getOperand(1)];
            std::copy(arg1.begin(), arg1.end(), input_vars.begin() + arg0.size());
            const auto &arg2 = frame.vectors[inst->getOperand(2)];
            std::copy(arg2.begin(), arg2.end(), input_vars.begin() + arg0.size() + arg1.size());

            typename sha2_512_component_type::var_ec_point R = {{{input_vars[0], input_vars[1], input_vars[2], input_vars[3]}},
                                                        {{input_vars[4], input_vars[5], input_vars[6], input_vars[7]}}};
            typename sha2_512_component_type::var_ec_point A = {{{input_vars[8], input_vars[9], input_vars[10], input_vars[11]}},
                                                      {{input_vars[12], input_vars[13], input_vars[14], input_vars[15]}}};

            typename sha2_512_component_type::input_type sha2_512_instance_input = {R, A, {{input_vars[16], input_vars[17],
                input_vars[18], input_vars[19]}}};

            sha2_512_component_type sha2_512_component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8}, {0}, {});

            components::generate_circuit(sha2_512_component_instance, bp, assignmnt, sha2_512_instance_input, start_row);

            typename sha2_512_component_type::result_type sha2_512_component_result =
                components::generate_assignments(sha2_512_component_instance, assignmnt, sha2_512_instance_input, start_row);

            using reduction_component_type = components::reduction<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, BlueprintFieldType, 9,
                basic_non_native_policy<BlueprintFieldType>>;

            reduction_component_type reduction_component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8}, {0}, {});

            start_row = assignmnt.allocated_rows();

            typename reduction_component_type::input_type reduction_instance_input = {sha2_512_component_result.output_state};

            components::generate_circuit(reduction_component_instance, bp, assignmnt, reduction_instance_input, start_row);

            typename reduction_component_type::result_type reduction_component_result =
                components::generate_assignments(reduction_component_instance, assignmnt, reduction_instance_input, start_row);

            frame.scalars[inst] = reduction_component_result.output;
        }
    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_HASHES_SHA2_512_HPP