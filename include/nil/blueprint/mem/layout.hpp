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
// ╔═════════════════════════════════════════════════════════════════════╗
// ║   Memory layout:                                                    ║
// ║                                                                     ║
// ║           stack pointer ──┐                  heap top ──┐           ║
// ║                           │                             │           ║
// ║ |--|++|++|++|++|++|.....|++|.....|--|++|++|++|++|.....|--|.....     ║
// ║  00 01                            ST HB                             ║
// ║   │  └─ stack bottom               │  └─ heap bottom (stack size)   ║
// ║   └──── null pointer               └──── stack top                  ║
// ╚═════════════════════════════════════════════════════════════════════╝
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ASSIGNER_MEM_LAYOUT_HPP
#define CRYPTO3_ASSIGNER_MEM_LAYOUT_HPP

#include <cstdint>
#include <limits>

namespace nil {
    namespace blueprint {
        namespace mem {
            /// @brief Address in memory.
            using ptr_type = std::uint64_t;

            /// @brief Bit width of address in memory.
            const int ptr_bit_width = std::numeric_limits<ptr_type>::digits;

            /// @brief Size of memory allocation in bytes.
            using size_type = std::uint32_t;

            /// @brief Maximum available address.
            const ptr_type PTR_MAX = std::numeric_limits<ptr_type>::max();

            /// @brief Null pointer.
            const ptr_type NULL_PTR = 0x0;

            /// @brief Pointer to the bottom of the stack.
            const ptr_type STACK_BOTTOM = 0x1;

            /// @brief Size of the stack.
            const size_type STACK_SIZE = 0x800000;

            /// @brief Pointer to the heap bottom.
            const ptr_type HEAP_BOTTOM = STACK_SIZE;
        }    // namespace mem
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_MEM_LAYOUT_HPP
