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

#ifndef CRYPTO3_ASSIGNER_FP12_MULTIPLICATION_HPP
#define CRYPTO3_ASSIGNER_FP12_MULTIPLICATION_HPP

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
        void handle_fp12_mul(
            const llvm::Instruction *inst,
            stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
            circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                &assignment,
                column_type<BlueprintFieldType> &internal_storage,
                component_calls &statistics,
                const common_component_parameters& param) {

                    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

                    using component_type = components::fp12_multiplication<
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                        BlueprintFieldType>;

                    std::vector<var> x = frame.vectors[inst->getOperand(0)];
                    ASSERT(x.size() == 12);

                    std::vector<var> y = frame.vectors[inst->getOperand(1)];
                    ASSERT(y.size() == 12);

                    std::array<var,12> x_arr = {
                        x[0],  x[1],  x[2],  x[3],
                        x[4],  x[5],  x[6],  x[7],
                        x[8],  x[9],  x[10], x[11]
                    };
                    std::array<var,12> y_arr = {
                        y[0],  y[1],  y[2],  y[3],
                        y[4],  y[5],  y[6],  y[7],
                        y[8],  y[9],  y[10], y[11]
                    };

                    typename component_type::input_type instance_input;
                    instance_input.a = x_arr;
                    instance_input.b = y_arr;

                    handle_component<BlueprintFieldType, component_type>
                        (bp, assignment, internal_storage, statistics, param, instance_input, inst, frame);
        }

    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_FP12_MULTIPLICATION_HPP
