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

#ifndef CRYPTO3_ASSIGNER_BLS12_381_PAIRING_HPP
#define CRYPTO3_ASSIGNER_BLS12_381_PAIRING_HPP

#include "llvm/IR/Type.h"
#include "llvm/IR/TypeFinder.h"
#include "llvm/IR/TypedPointerType.h"

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/curves/curve25519.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>

#include <nil/blueprint/handle_component.hpp>

namespace nil {
    namespace blueprint {

        template<typename BlueprintFieldType>
        void handle_bls12381_pairing(
            const llvm::Instruction *inst,
            stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
            circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                &assignment,
                component_calls &statistics,
                const common_component_parameters& param) {

                    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

                    using component_type = components::bls12_381_pairing<
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                        BlueprintFieldType>;

                    ASSERT(frame.vectors[inst->getOperand(0)].size() == 2);
                    ASSERT(frame.vectors[inst->getOperand(1)].size() == 4);
                    std::vector<var> operand0_vars = frame.vectors[inst->getOperand(0)];
                    std::vector<var> operand1_vars = frame.vectors[inst->getOperand(1)];

                    std::array<var,2> P = {
                                            operand0_vars[0],
                                            operand0_vars[1]};
                    std::array<var,4> Q = {
                                            operand1_vars[0],
                                            operand1_vars[1],
                                            operand1_vars[2],
                                            operand1_vars[3]};

                    typename component_type::input_type instance_input;
                    instance_input.P = P;
                    instance_input.Q = Q;

                    handle_component<BlueprintFieldType, component_type>
                        (bp, assignment, statistics, param, instance_input, inst, frame);
        }

    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_BLS12_381_PAIRING_HPP
