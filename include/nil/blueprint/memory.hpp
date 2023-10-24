//---------------------------------------------------------------------------//
// Copyright (c) 2023 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2023 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2023 Mikhail Aksenov <maksenov@nil.foundation>
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

#ifndef CRYPTO3_ASSIGNER_MEMORY_HPP
#define CRYPTO3_ASSIGNER_MEMORY_HPP

#include <cstddef>
#include <unordered_map>
#include <vector>
#include <stack>
#include <algorithm>

#include <nil/blueprint/asserts.hpp>

namespace nil {
    namespace blueprint {
        using ptr_type = unsigned;

        template<typename VarType>
        struct cell {
            VarType v;
            size_t offset;
            int8_t head;
        };

        template<typename VarType>
        struct program_memory : public std::vector<cell<VarType>> {
        public:
            program_memory(long stack_size) : stack_size(stack_size), heap_top(stack_size) {
                // pad stack size to multiple of alignof(std::max_align_t), so heap_top is aligned correctly
                constexpr auto alignment = alignof(std::max_align_t);
                this->stack_size += alignment - 1;
                this->stack_size = (this->stack_size / alignment) * alignment;
                this->heap_top = this->stack_size;

                // We cell's offset is (actual_offset + size), so we add initial cell with zero offset
                // to easily compute a size of a cell as a difference with the previous one
                this->push_back({VarType(), 0});
                this->resize(heap_top);
                push_frame();
            }
            void stack_push(unsigned offset) {
                cell<VarType> &new_cell = this->operator[](stack_top++);
                new_cell.offset = offset;
                new_cell.head = 1;
            }

            void push_frame() {
                frames.push(stack_top);
            }

            void pop_frame() {
                stack_top = frames.top();
                frames.pop();
            }

            ptr_type add_cells(const std::vector<unsigned> &layout) {
                ptr_type res = stack_top;
                unsigned acc = this->at(stack_top - 1).offset;
                for (unsigned cell_size : layout) {
                    acc += cell_size;
                    stack_push(acc);
                }
                return res;
            }

            ptr_type malloc(size_t num_bytes) {
                // pad malloc size to multiple of alignof(std::max_align_t)
                // so following mallocs are aligned correctly
                constexpr auto alignment = alignof(std::max_align_t);
                num_bytes += alignment - 1;
                num_bytes = (num_bytes / alignment) * alignment;

                auto offset = this->back().offset;
                ptr_type res = this->size();
                for (size_t i = 0; i < num_bytes; ++i) {
                    this->push_back(cell<VarType> {VarType(), offset++, 1});
                }
                return res;
            }

            void store(ptr_type ptr, VarType value) {
                (*this)[ptr].v = value;
            }
            VarType load(ptr_type ptr) {
                return (*this)[ptr].v;
            }

            size_t ptrtoint(ptr_type ptr) {
                // Actual offset is stored in the previous cell
                return (*this)[ptr - 1].offset;
            }

            ptr_type inttoptr(size_t offset) {
                // Find the corresponding cell using binary search
                auto left = this->begin();
                auto right = this->end();
                if (offset < stack_size) {
                    right = left + stack_top;
                } else {
                    left = left + stack_size;
                }
                auto res = std::lower_bound(
                    left, right, offset, [](const cell<VarType> &cell, size_t offset) { return cell.offset < offset; });
                if (res == right) {
                    return 0;
                }
                // The operation is inverse to ptrtoint, so we need to add 1 to get the desired ptr
                return res - left + 1;
            }

        private:
            ptr_type stack_top = 1;
            size_t stack_size;
            size_t heap_top;
            std::stack<ptr_type> frames;
        };

    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_MEMORY_HPP
