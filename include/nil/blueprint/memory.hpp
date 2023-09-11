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

#include <unordered_map>
#include <vector>
#include <stack>

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
            program_memory(long stack_size) : heap_top(stack_size) {
                this->push_back({VarType(), 0});
                this->resize(heap_top);
                push_frame();
            }
            void stack_push(unsigned offset) {
                this->operator[](stack_top++) = cell<VarType> {VarType(), offset, 1};
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
                auto offset = this->back().offset;
                ptr_type res = this->size();
                for (size_t i = 0; i < num_bytes; ++i) {
                    this->push_back(cell<VarType>{VarType(), offset++, 1});
                }
                return res;
            }

            void store(ptr_type ptr, VarType value) {
                this->operator[](ptr).v = value;
            }
            VarType load(ptr_type ptr) {
                return this->operator[](ptr).v;
            }

        private:
            ptr_type stack_top = 1;
            size_t heap_top;
            std::stack<ptr_type> frames;
        };

    }    // namespace blueprint
}    // namespace nil

#endif  // CRYPTO3_ASSIGNER_MEMORY_HPP
