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

#ifndef ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_MEMORY_HPP_
#define ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_MEMORY_HPP_

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
            std::optional<VarType> v;
            size_t offset;
            int8_t size;
            int8_t following;
        };

        template<typename VarType>
        struct memory_state {
            ptr_type stack_top;
            size_t heap_top;
            std::stack<ptr_type> frames;
            std::vector<cell<VarType>> heap;
            std::vector<cell<VarType>> stack;
        };

        template<typename VarType>
        struct program_memory : public std::vector<cell<VarType>> {
        public:
            program_memory(size_t stack_size) : stack_size(stack_size), heap_top(stack_size) {
                this->push_back({std::nullopt, 0, 0});
                this->resize(heap_top);
                this->push_back({std::nullopt, stack_size + 1, 0});
                heap_top++;
                push_frame();
            }

            void push_frame() {
                frames.push(stack_top);
            }

            void pop_frame() {
                stack_top = frames.top();
                frames.pop();
            }

            ptr_type add_cells(const std::vector<std::pair<unsigned, unsigned>> &layout) {
                ptr_type res = stack_top;
                ASSERT_MSG(stack_top < stack_size, "Stack size exceeded! (use -s command line argument to define stack size)");
                unsigned next_offset = this->at(stack_top - 1).offset + this->at(stack_top - 1).size;
                for (auto [cell_size, following] : layout) {
                    stack_push(next_offset, cell_size, following);
                    for (unsigned i = 1; i <= following; ++i) {
                        stack_push(next_offset, 0, following - i);
                    }
                    next_offset += cell_size;
                }
                return res;
            }

            ptr_type malloc(size_t num_bytes) {
                auto offset = this->back().offset + this->back().size;
                ptr_type res = this->size();
                for (size_t i = 0; i < num_bytes; ++i) {
                    this->push_back(cell<VarType>{std::nullopt, offset++, 1});
                    heap_top++;
                }
                return res;
            }

            void store(ptr_type ptr, VarType value) {
                (*this)[ptr].v = value;
            }

            VarType load(ptr_type ptr) {
                auto maybe_v = (*this)[ptr].v;
                ASSERT(maybe_v.has_value());
                return maybe_v.value();
            }

            size_t ptrtoint(ptr_type ptr) {
                return (*this)[ptr].offset;
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
                return res - this->begin();
            }

            void get_current_state(memory_state<VarType> &state) const {
                state.stack_top = stack_top;
                state.heap_top = heap_top;
                state.frames = frames;
                state.stack.resize(stack_top);
                for (ptr_type i = 1; i < stack_top; i++) {
                    state.stack[i - 1] = (*this)[i];
                }
                state.heap.resize(heap_top - stack_size);
                for (ptr_type i = stack_size + 1; i < heap_top; i++) {
                    state.heap[i - stack_size - 1] = (*this)[i];
                }
            }

            void restore_state(const memory_state<VarType> &state) {
                this->resize(state.heap_top);
                frames = state.frames;
                for (ptr_type i = 0; i < state.stack.size(); i++) {
                    if (i < state.stack.size()) {
                        (*this)[i + 1] = state.stack[i];
                    } else {
                        (*this)[i + 1] = cell<VarType>();
                    }
                }
                for (ptr_type i = 0; i < state.heap.size(); i++) {
                    (*this)[i + stack_size + 1] = state.heap[i];
                }
                heap_top = state.heap_top;
                stack_top = state.stack_top;
            }

            ptr_type get_stack_top() const {
                return stack_top;
            }

            size_t get_heap_top() const {
                return heap_top;
            }

            const std::stack<ptr_type>& get_frames() const {
                return frames;
            }

            size_t get_stack_size() const {
                return stack_size;
            }

        private:

            void stack_push(size_t offset, int8_t size, int8_t following) {
                cell<VarType> &new_cell = this->operator[](stack_top++);
                new_cell.offset = offset;
                new_cell.size = size;
                new_cell.following = following;
            }

            ptr_type stack_top = 1;
            size_t stack_size;
            size_t heap_top;
            std::stack<ptr_type> frames;
        };

    }    // namespace blueprint
}    // namespace nil

#endif  // ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_MEMORY_HPP_
