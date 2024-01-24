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

#ifndef NIL_BLUEPRINT_MEM_MEMORY_HPP
#define NIL_BLUEPRINT_MEM_MEMORY_HPP

#include <stack>

#include <nil/blueprint/mem/allocator.hpp>
#include <nil/blueprint/mem/layout.hpp>
#include <nil/blueprint/mem/segment.hpp>
#include <nil/blueprint/mem/segment_map.hpp>

namespace nil {
    namespace blueprint {
        namespace mem {
            /// Core structure representing assigner memory.
            template<typename VarType>
            struct memory {
            private:
                segment_map<VarType> storage;

                allocator<VarType> alloc;

                /// Stack pointer.
                ptr_type stack_ptr;

                /// Stack frames.
                std::stack<ptr_type> frames;

            public:
                memory() : stack_ptr(STACK_BOTTOM) {
                    this->alloc = allocator<VarType>(this->storage);
                    this->push_frame();
                }

                /// Get allocator reference.
                allocator<VarType>& get_allocator() {
                    return alloc;
                }

                /// Push new stack frame.
                void push_frame() {
                    frames.push(stack_ptr);
                }

                /// Pop last stack frame.
                void pop_frame() {
                    stack_ptr = frames.top();
                    frames.pop();
                }

                /// Allocate N bytes on stack and return pointer to this.
                ptr_type stack_alloca(size_type n) {
                    ptr_type ptr = stack_ptr;
                    stack_ptr += n;
                    return ptr;
                }

                /// Store value of given size at given pointer.
                void store(ptr_type ptr, size_type size, VarType value) {
                    storage.insert(segment(ptr, size), value);
                }

                /// Load value of given size from given pointer.
                VarType load(ptr_type ptr, size_type size) {
                    return storage.get(segment(ptr, size));
                }

                /// Set first `count` bytes from `dest` to `value`.
                void memset(ptr_type dest, VarType value, size_type count) {
                    UNREACHABLE("memset not yet implemented");
                }

                /// Copy `count` bytes from `src` to `dest`.
                void memcpy(ptr_type dest, ptr_type src, size_type count) {
                    UNREACHABLE("memcpy not yet implemented");
                }
            };
        }    // namespace mem
    }        // namespace blueprint
}    // namespace nil

#endif    // NIL_BLUEPRINT_MEM_MEMORY_HPP
