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
// @file This file defines assigner memory representation.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ASSIGNER_MEM_MEMORY_HPP
#define CRYPTO3_ASSIGNER_MEM_MEMORY_HPP

#include <stack>

#include <nil/blueprint/asserts.hpp>
#include <nil/blueprint/mem/layout.hpp>
#include <nil/blueprint/mem/segment.hpp>
#include <nil/blueprint/mem/segment_map.hpp>
#include <nil/blueprint/mem/var.hpp>

namespace nil {
    namespace blueprint {
        namespace mem {
            /// Core structure representing assigner memory.
            template<typename VarType>
            struct memory {
                using var_type = var<VarType>;

            private:
                segment_map<var_type> segments;
                size_type stack_size;
                ptr_type stack_ptr;
                std::stack<ptr_type> frames;

            public:
                memory(size_type stack_size) : stack_size(stack_size), stack_ptr(0) {
                }

                void store(ptr_type ptr, VarType value, size_type size) {
                    if (auto seg = segments.find_segment(ptr)) {
                        segments.insert({segment(ptr, size), var_type(value, size)});
                    } else {
                        UNREACHABLE("accessing out of allocated memory");
                    }
                }

                var_type load(ptr_type ptr) {
                    UNREACHABLE("not yet implemented");
                }
            };
        }    // namespace mem
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_MEM_MEMORY_HPP
