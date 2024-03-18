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

#ifndef ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_STACK_HPP_
#define ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_STACK_HPP_

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Value.h"

#include <map>
#include <vector>

namespace nil {
    namespace blueprint {
        /**
         * @brief Execution frame. Each function call uses its own `stack_frame`, which holds
         * local variables.
         */
        template<typename VarType>
        struct stack_frame {
            /// @brief Type representing scalar registers.
            using scalar_regs = std::map<const llvm::Value *, VarType>;

            /// @brief Type representing vector registers.
            using vector_regs = std::map<const llvm::Value *, std::vector<VarType>>;

            /// @brief Registers holding scalar values (integers, pointers, native fields).
            scalar_regs scalars;

            /// @brief Registers holding vector values (non-native fields, curves, vectors, etc.).
            vector_regs vectors;

            const llvm::CallInst *caller;
        };

    }    // namespace blueprint
}    // namespace nil

#endif    // ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_STACK_HPP_
