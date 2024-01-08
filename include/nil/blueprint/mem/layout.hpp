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
// @file This file declares memory properties such as pointer size.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ASSIGNER_MEM_LAYOUT_HPP
#define CRYPTO3_ASSIGNER_MEM_LAYOUT_HPP

#include <cstdint>

namespace nil {
    namespace blueprint {
        namespace mem {
            /* Pointer type in memory.
             *
             * We intentionally enforce fixed-size type here.
             */
            using ptr_type = std::uint64_t;

            /* Size of memory allocation in bytes.
             *
             * Used to distinguish between pointers and sizes. We intentionally enforce fixed-size
             * type here.
             */
            using size_type = std::uint32_t;
        }    // namespace mem
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_MEM_LAYOUT_HPP
