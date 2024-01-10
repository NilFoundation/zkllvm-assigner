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
// ╔═════════════════════════════════════════════════════════════════╗
// ║   Memory layout:                                                ║
// ║                                                                 ║
// ║           stack pointer ──┐                  heap top ──┐       ║
// ║                           │                             │       ║
// ║ |--|++|++|++|++|++|.....|++|.....|--|++|++|++|++|.....|--|..... ║
// ║  00 01                            ST HB                         ║
// ║   │  └─ stack bottom               │  └─ heap bottom            ║
// ║   └──── null pointer               └──── stack top (stack size) ║
// ╚═════════════════════════════════════════════════════════════════╝
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
            private:
                using var_type = var<VarType>;
                /// Allocated segments.
                segment_map<VarType> segments;

                /// Size of preallocated stack memory.
                size_type stack_size;

                /// Stack pointer.
                ptr_type stack_ptr;

                /// Next free heap pointer.
                ptr_type heap_top;

                /// Stack frames.
                std::stack<ptr_type> frames;

            public:
                memory(size_type stack_size) : stack_size(stack_size), stack_ptr(0x1), heap_top(stack_size + 1) {
                    // Pre-allocated stack segment
                    // TODO: maybe we don't need this pre-allocation?
                    this->segments.insert({segment(0x1, stack_size), var_type()});
                    this->push_frame();
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
                ptr_type stack_push(size_type n) {
                    ptr_type ptr = stack_ptr;
                    segment alloc(ptr, n);
                    this->segments[alloc] = var_type();
                    stack_ptr += n;
                    return ptr;
                }

                void store(ptr_type ptr, size_type size, VarType value) {
                    if (auto seg = segments.find_segment(ptr)) {
                        segments.insert({segment(ptr, size), var_type(value, size)});
                    } else {
                        UNREACHABLE("out of allocated memory access");
                    }
                }

                VarType load(ptr_type ptr, size_type size) {
                    auto elem = segments.find(segment(ptr, size));
                    if (elem == segments.end()) {
                        if (auto seg = segments.find_segment(ptr)) {
                            UNREACHABLE("unaligned loads are not yet implemented");
                        } else {
                            UNREACHABLE("out of allocated memory access");
                        }
                    }
                    return elem->second.value;
                }

                // This gonna be removed, used only for debug.
                // Print current memory state summary to stdout.
                void dump_summary() {
                    std::cout << "================================================" << std::endl;
                    std::cout << "Stack size: 0x" << std::hex << stack_size << std::endl;
                    std::cout << "Heap top: 0x" << std::hex << heap_top << std::endl;
                    std::cout << "Stack pointer: 0x" << std::hex << stack_ptr << std::dec << std::endl;
                    std::cout << "Frames count: " << frames.size() << std::endl;
                    std::cout << "Segments count: " << segments.size() << std::endl;
                    std::cout << std::endl;
                    std::cout << "Segments:" << std::endl;
                    for(const auto& elem : segments) {
                        std::cout << "  " << elem.first << " = " << elem.second.value << std::endl;
                    }
                    std::cout << "================================================" << std::endl;
                }
            };
        }    // namespace mem
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_MEM_MEMORY_HPP
