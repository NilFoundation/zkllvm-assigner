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

#ifndef CRYPTO3_ASSIGNER_GEP_RESOLVER_HPP
#define CRYPTO3_ASSIGNER_GEP_RESOLVER_HPP

#include <vector>
#include <unordered_map>

#include "llvm/IR/Constant.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/GlobalVariable.h"

#include <nil/blueprint/asserts.hpp>

namespace nil {
    namespace blueprint {
        // This class is intended to compute flat offsets for GEP instruction
        // to put elements of struct/array into a chunk with a correct index.
        // For example, if we have a type { i32, [2 x i32], %pointer* }
        // and the GEP instruction retrieves a pointer element (with index 2 inside the struct),
        // the answer must be 3, because we have a complex field with size 2 at the index 1
        class GepResolver {
            struct Element {
                const llvm::Type *type;
                unsigned idx;
            };
            struct IndexMapping {
                std::vector<Element> indices;
                unsigned size;
            };

        public:
            GepResolver() = default;
            int get_flat_index(const llvm::Type *type, const std::vector<int> &gep_indices) {
                ASSERT(type->isAggregateType());
                if (type_cache.find(type) == type_cache.end())
                    resolve_type(type);
                auto *type_record = &type_cache[type];
                for (unsigned i = 0; i < gep_indices.size() - 1; ++i) {
                    type_record = &type_cache[type_record->indices[i].type];
                }
                return type_record->indices[gep_indices.size() - 1].idx;
            }

            unsigned get_type_size(const llvm::Type *type) {
                if (!type->isAggregateType())
                    return 1;
                if (type_cache.find(type) == type_cache.end())
                    return resolve_type(type);
                return type_cache[type].size;
            }

            GepResolver(const GepResolver &) = delete;
            GepResolver(GepResolver &&) = delete;

        private:
            unsigned resolve_type(const llvm::Type *type) {
                if (!type->isAggregateType()) {
                    // End of recursion
                    return 1;
                }
                if (type_cache.find(type) != type_cache.end()) {
                    return type_cache[type].size;
                }
                IndexMapping cache_data {{}, 0};
                if (auto *array_ty = llvm::dyn_cast<llvm::ArrayType>(type)) {
                    const llvm::Type *elem_ty = array_ty->getElementType();
                    unsigned elem_size = resolve_type(elem_ty);
                    cache_data.size = array_ty->getNumElements() * elem_size;
                    cache_data.indices.resize(array_ty->getNumElements());
                    for (unsigned i = 0; i < array_ty->getNumElements(); ++i) {
                        cache_data.indices[i].idx = i * elem_size;
                        cache_data.indices[i].type = elem_ty;
                    }
                    type_cache[type] = cache_data;
                    return cache_data.size;
                }
                auto *struct_ty = llvm::cast<llvm::StructType>(type);

                unsigned prev = 0;
                cache_data.indices.resize(struct_ty->getNumElements());
                for (unsigned i = 0; i < struct_ty->getNumElements(); ++i) {
                    auto elem_ty = struct_ty->getElementType(i);
                    cache_data.size += resolve_type(elem_ty);;
                    cache_data.indices[i] = {elem_ty,prev};
                    prev = cache_data.size;
                }
                type_cache[type] = cache_data;
                return cache_data.size;

            }
            std::unordered_map<const llvm::Type *, IndexMapping> type_cache;
        };
    }
}    // namespace nil

#endif  // CRYPTO3_ASSIGNER_GEP_RESOLVER_HPP
