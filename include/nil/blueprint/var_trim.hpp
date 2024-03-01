//---------------------------------------------------------------------------//
// Copyright (c) 2023 Alexander Evgin <aleasims@nil.foundation>
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
// @file This file defines class responsible for generation of PLONK variable
// for trimmed variable. E.g. you have variable `a` of size 8 bytes and you
// want to generate a variable for byte slice `a[0:4]`.
//---------------------------------------------------------------------------//

#ifndef ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_VAR_TRIM_HPP_
#define ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_VAR_TRIM_HPP_

#include <nil/blueprint/asserts.hpp>
#include <nil/blueprint/mem/layout.hpp>

namespace nil {
    namespace blueprint {
        /**
         * @brief Trimmer of a variables.
         * This class responsible for generation of trimmed variables.
         *
         * @tparam Var type representing variable to trim
         */
        template<typename Var>
        struct VarTrim {
        public:
            VarTrim() {
            }

            /**
             * @brief Generate new variable in assignment table, which equals to byte slice
             * of given variable. Little-endian assumed.
             *
             * @param variable input variable
             * @param start start of the byte slize (included)
             * @param end end of the byte slice (not included)
             *
             * @return generated variable equals to `variable[start:end]` byte slice
             */
            Var trim(Var variable, mem::size_type start, mem::size_type end) {
                // TODO: implement variable trimming;
                return variable;
            }
        };
    }    // namespace blueprint
}    // namespace nil

#endif    // ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_VAR_TRIM_HPP_
