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

#include <nil/blueprint/asserts.hpp>

namespace nil {
    namespace blueprint {

        template<typename VarType>
        class Chunk;

        template <typename VarType>
        class Pointer {
            Chunk<VarType> *base;
            unsigned index;

        public:
            Pointer<VarType>(Chunk<VarType>* c, unsigned i): base(c), index(i) {}
            Pointer<VarType>(): base(nullptr), index(0) {}
            Pointer<VarType> adjust(int idx) {
                return Pointer<VarType>(base, index + idx);
            }
            Chunk<VarType> *get_base() {
                return base;
            }
            VarType load_var();
            Pointer<VarType> load_pointer();
            std::vector<VarType> load_vector();
            void store_var(const VarType &variable);
            void store_pointer(const Pointer<VarType> &ptr);
            void store_vector(const std::vector<VarType> &vector);

            void memcpy(Chunk<VarType> *mem);
            void memcpy(Pointer<VarType> ptr);

            bool operator==(const Pointer<VarType> &other) const {
                return base == other.base && index == other.index;
            }
        };

        template <typename VarType>
        class Chunk {
            std::unordered_map<unsigned, Pointer<VarType>> links;
            std::unordered_map<unsigned, VarType> data;
            std::unordered_map<unsigned, std::vector<VarType>> vectors;

        public:
            VarType load_var(unsigned idx) {
                return data[idx];
            }
            Pointer<VarType> load_pointer(unsigned idx) {
                return links[idx];
            }
            std::vector<VarType> load_vector(unsigned idx) {
                return vectors[idx];
            }
            void store_var(const VarType &variable, unsigned idx) {
                data[idx] = variable;
            }
            void store_pointer(const Pointer<VarType> &ptr, unsigned idx) {
                links[idx] = ptr;
            }
            void store_vector(const std::vector<VarType> &vec, unsigned idx) {
                vectors[idx] = vec;
            }
            void memcpy(Chunk<VarType> *other) {
                links.clear();
                data.clear();
                vectors.clear();

                for (const auto &[key, val] : other->links) {
                    links[key] = val;
                }
                for (const auto &[key, val] : other->data) {
                    data[key] = val;
                }
                for (const auto &[key, val] : other->vectors) {
                    vectors[key] = val;
                }
            }
        };

        template<typename VarType>
        inline VarType Pointer<VarType>::load_var() {
            return base->load_var(index);
        }
        template<typename VarType>
        inline Pointer<VarType> Pointer<VarType>::load_pointer() {
            return base->load_pointer(index);
        }
        template<typename VarType>
        inline std::vector<VarType> Pointer<VarType>::load_vector() {
            return base->load_vector(index);
        }
        template<typename VarType>
        inline void Pointer<VarType>::store_var(const VarType &variable) {
            base->store_var(variable, index);
        }
        template<typename VarType>
        inline void Pointer<VarType>::store_pointer(const Pointer<VarType> &ptr) {
            base->store_pointer(ptr, index);
        }
        template<typename VarType>
        inline void Pointer<VarType>::store_vector(const std::vector<VarType> &vec) {
            base->store_vector(vec, index);
        }
        template<typename VarType>
        inline void Pointer<VarType>::memcpy(Chunk<VarType> *mem) {
            ASSERT(index == 0);
            base->memcpy(mem);
        }
        template<typename VarType>
        inline void Pointer<VarType>::memcpy(Pointer<VarType> mem) {
            ASSERT(mem.index == 0);
            base->memcpy(mem.base);
        }

    }    // namespace blueprint
}    // namespace nil

#endif  // CRYPTO3_ASSIGNER_MEMORY_HPP
