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
        template<typename VarType>
        void handle_curve_init(const llvm::CallInst *inst, stack_frame<VarType> &frame) {
            VarType x = frame.scalars[inst->getOperand(0)];
            VarType y = frame.scalars[inst->getOperand(1)];
            frame.vectors[inst] = {x, y};
        }
    }
}

#endif // CRYPTO3_ASSIGNER_NIL_BLUEPRINT_CURVE_INIT_HPP
