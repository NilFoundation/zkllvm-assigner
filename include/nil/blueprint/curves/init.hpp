//---------------------------------------------------------------------------//
// Copyright (c) 2023 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2023 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2023 Mikhail Aksenov <maksenov@nil.foundation>
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

#ifndef CRYPTO3_ASSIGNER_NIL_BLUEPRINT_CURVE_INIT_HPP
#define CRYPTO3_ASSIGNER_NIL_BLUEPRINT_CURVE_INIT_HPP

#include <nil/blueprint/stack.hpp>

namespace nil {
    namespace blueprint {
        template<typename VarType, typename BlueprintFieldType>
        void handle_curve_init(const llvm::CallInst *inst, stack_frame<VarType> &frame) {
            ASSERT(inst->getOperand(0)->getType() == inst->getOperand(1)->getType());
            ASSERT(inst->getOperand(0)->getType()->isFieldTy());

            std::size_t arg_num = field_arg_num<BlueprintFieldType>(inst->getOperand(0)->getType());
            if (arg_num == 1) {
                VarType x = frame.scalars[inst->getOperand(0)];
                VarType y = frame.scalars[inst->getOperand(1)];
                frame.vectors[inst] = {x, y};
            }
            else {
                ASSERT(frame.vectors[inst->getOperand(0)].size() == frame.vectors[inst->getOperand(1)].size());
                std::vector<VarType> vect0 = frame.vectors[inst->getOperand(0)];
                std::vector<VarType> vect1 = frame.vectors[inst->getOperand(1)];
                vect0.insert(vect0.end(), vect1.begin(), vect1.end());
                frame.vectors[inst] = vect0;
            }
        }

    } // namespace blueprint
} // namespace nil

#endif // CRYPTO3_ASSIGNER_NIL_BLUEPRINT_CURVE_INIT_HPP
