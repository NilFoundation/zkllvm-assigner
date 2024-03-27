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

#ifndef ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_MEM_MEMORY_HPP_
#define ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_MEM_MEMORY_HPP_

#include <nil/blueprint/mem/allocator.hpp>
#include <nil/blueprint/mem/layout.hpp>
#include <nil/blueprint/mem/segment.hpp>
#include <nil/blueprint/mem/segment_map.hpp>

#include <nil/blueprint/asserts.hpp>

#include <stack>

namespace nil {
    namespace blueprint {
        namespace mem {
            /**
             * @brief Core structure representing assigner memory.
             *
             * @tparam ValueRepr type representing single native value
             */
            template<typename VarType>
            struct program_memory {
            private:
                /// Memory storage.
                segment_map<VarType> storage;

                /// Heap memory allocator.
                allocator<VarType> alloc;

                /// Stack pointer.
                ptr_type stack_ptr;

                /// Stack frames.
                std::stack<ptr_type> frames;

            public:
                program_memory() : alloc(this->storage), stack_ptr(STACK_BOTTOM) {
                    push_frame();
                }

                /// @brief Get allocator reference.
                allocator<VarType>& get_allocator() {
                    return alloc;
                }

                /// @brief Push new stack frame.
                void push_frame() {
                    frames.push(stack_ptr);
                }

                /// @brief Pop last stack frame.
                void pop_frame() {
                    stack_ptr = frames.top();
                    frames.pop();
                }

                /// @brief Allocate N bytes on stack and return pointer to this.
                ptr_type stack_alloca(size_type n) {
                    ptr_type ptr = stack_ptr;
                    stack_ptr += n;
                    return ptr;
                }

                /// @brief Store value of given size at given pointer.
                void store(ptr_type ptr, size_type size, VarType value) {
                    storage.insert(segment(ptr, size), value);
                }

                /// @brief Load value of given size from given pointer.
                VarType load(ptr_type ptr, size_type size) {
                    return storage.get(segment(ptr, size));
                }

                /// @brief Set first `count` bytes from `dest` to `value`.
                void memset(ptr_type dest, VarType value, size_type count) {
                    for(size_type i = 0; i < count; ++i) {
                        storage.insert(segment(dest + i, 1), value);
                    }
                }

                /// @brief Copy `count` bytes from `src` to `dest`.
                void memcpy(ptr_type dest, ptr_type src, size_type count) {
                    // Source segment
                    segment src_seg(src, count);
                    // Collection of all segments in the storage intersecting with segment
                    std::map<segment, VarType> intersections = storage.find_intersections(src_seg);

                    // We cannot correctly subtruct pointers as signed integers, so we store the sign
                    // of the difference separately.
                    bool diff_sign = dest > src;
                    ptr_type diff;
                    if (diff_sign) {
                        diff = dest - src;
                    } else {
                        diff = src - dest;
                    }
                    // Apply difference to a pointer with respect to difference sign.
                    auto apply_diff = [diff, diff_sign](ptr_type &ptr) {
                        if (diff_sign) {
                            ptr_type new_ptr = ptr + diff;
                            ASSERT_MSG(new_ptr >= ptr, "out of memory at memcpy");
                            ptr = new_ptr;
                        } else {
                            ptr_type new_ptr = ptr - diff;
                            ASSERT_MSG(new_ptr <= ptr, "out of memory at memcpy");
                            ptr = new_ptr;
                        }
                    };

                    for (const auto& elem : intersections) {
                        segment seg = elem.first;
                        VarType value = elem.second;

                        if (src_seg.contains(seg)) {
                            // `seg` is an inner part of the source segment, so we copy it all
                            segment seg_copy = seg;
                            apply_diff(seg_copy.pointer);
                            storage.insert(seg_copy, value);
                        } else {
                            // `seg` only intersects with source segment, so we copy a part of it
                            TODO("partial copy of a segment at memcpy");
                        }
                    }
                }
            };
        }    // namespace mem
    }        // namespace blueprint
}    // namespace nil

#endif    // ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_MEM_MEMORY_HPP_
