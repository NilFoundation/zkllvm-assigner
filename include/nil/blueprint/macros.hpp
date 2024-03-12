//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexander Evgin <aleasims@nil.foundation>
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
// @file This file defines some helpful macros, used in assigner.
//---------------------------------------------------------------------------//

#ifndef ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_MACROS_HPP_
#define ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_MACROS_HPP_

#include "llvm/Support/raw_ostream.h"

#include <string>

/**
 * @brief This macro calls `print` function of LLVM printable entity and stores result into
 * created string with name `output`.
 *
 * @param obj object, which can be printed with `obj->print()`
 * @param output name of the output string
 */
#define LLVM_PRINT(obj, output)            \
    std::string output;                           \
    llvm::raw_string_ostream ss_##output(output); \
    obj->print(ss_##output);

#endif    // ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_MACROS_HPP_
