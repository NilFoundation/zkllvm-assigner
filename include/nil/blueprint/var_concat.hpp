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
// for concatenation of a number of variables. E.g. you have variables `a` and
// `b` of size 8 bytes and you want to generate a 16 byte variable for their
// byte concatenation.
//---------------------------------------------------------------------------//

#ifndef ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_VAR_CONCAT_HPP_
#define ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_VAR_CONCAT_HPP_

#include <nil/blueprint/asserts.hpp>
#include <nil/blueprint/mem/layout.hpp>

#include <vector>

namespace nil {
    namespace blueprint {
        /**
         * @brief Concatenator of a variables.
         * This class responsible for generation of concatenated variable.
         *
         * @tparam Var type representing variables to concatenate
         */
        template<typename Var>
        struct VarConcat {
        public:
            VarConcat() {
            }

            /**
             * @brief Generate new variable in assignment table, which equals to byte concatenation
             * of given variables.
             *
             * @param variables input variables
             * @param sizes byte sizes of corresponding variables
             *
             * @return generated variable equals to byte concatenation of given variables
             */
            Var concat(std::vector<Var> variables, std::vector<mem::size_type> sizes) {
                TODO("variables concatenation");
            }
        };
    }
}

#endif  // ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_VAR_CONCAT_HPP_
