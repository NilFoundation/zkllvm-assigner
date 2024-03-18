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

#ifndef ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_LAYOUT_RESOLVER_HPP_
#define ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_LAYOUT_RESOLVER_HPP_

#include <vector>
#include <unordered_map>

#include "llvm/IR/Constant.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/GlobalVariable.h"

#include <nil/blueprint/basic_non_native_policy.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/ed25519.hpp>

#include "nil/crypto3/algebra/fields/pallas/base_field.hpp"

#include <nil/blueprint/asserts.hpp>

#include <nil/blueprint/non_native_marshalling.hpp>

namespace nil {
    namespace blueprint {
        using type_layout = std::vector<std::pair<unsigned, unsigned>>;

        // This class is intended to compute flat offsets for GEP instruction
        // to put elements of struct/array into a chunk with a correct index.
        // For example, if we have a type { i32, [2 x i32], %pointer* }
        // and the GEP instruction retrieves a pointer element (with index 2 inside the struct),
        // the answer must be 3, because we have a complex field with size 2 at the index 1
        class LayoutResolver {
            struct Element {
                const llvm::Type *type;
                unsigned idx;
                unsigned offset;
            };
            struct IndexMapping {
                std::vector<Element> indices;
                unsigned size;
                unsigned width;
            };

        public:
            LayoutResolver(const llvm::DataLayout &layout): layout(layout) {}
            template <typename BlueprintFieldType, typename Array>
            std::pair<unsigned, int> resolve_offset_with_index_hint(llvm::Type *type, const Array &gep_indices) {
                ASSERT(type->isAggregateType());
                unsigned offset = 0;
                if (type_cache.find(type) == type_cache.end())
                    resolve_type<BlueprintFieldType>(type);
                auto *type_record = &type_cache[type];
                for (unsigned i = 0; i < gep_indices.size() - 1; ++i) {
                    offset += type_record->indices[gep_indices[i]].offset;
                    type_record = &type_cache[type_record->indices[gep_indices[i]].type];
                }
                return {type_record->indices[gep_indices.back()].offset + offset, type_record->indices[gep_indices.back()].idx};
            }

            unsigned get_type_size(llvm::Type *type) {
                return layout.getTypeStoreSize(type);
            }

            template <typename BlueprintFieldType>
            type_layout get_type_layout(llvm::Type *type) {
                // TODO(maksenov): add type cache
                switch (type->getTypeID()) {
                case llvm::Type::IntegerTyID:
                case llvm::Type::PointerTyID:
                    return {{get_type_size(type), 0}};
                case llvm::Type::GaloisFieldTyID: {
                    return {{get_type_size(type), field_arg_num<BlueprintFieldType>(type) - 1}};
                }
                case llvm::Type::EllipticCurveTyID: {
                    return {{get_type_size(type), curve_arg_num<BlueprintFieldType>(type) - 1}};
                }
                case llvm::Type::StructTyID: {
                    auto *struct_ty = llvm::cast<llvm::StructType>(type);
                    type_layout res;
                    for (size_t i = 0; i < struct_ty->getNumElements(); ++i) {
                        type_layout offf = get_type_layout<BlueprintFieldType>(struct_ty->getElementType(i));
                        res.insert(res.end(), offf.begin(), offf.end());
                    }
                    return res;
                }
                case llvm::Type::ArrayTyID: {
                    auto *array_ty = llvm::cast<llvm::ArrayType>(type);
                    llvm::Type *elem_ty = array_ty->getElementType();
                    type_layout elem_layout = get_type_layout<BlueprintFieldType>(elem_ty);
                    type_layout res;
                    for (size_t i = 0; i < array_ty->getNumElements(); ++i) {
                        res.insert(res.end(), elem_layout.begin(), elem_layout.end());
                    }
                    return res;
                }
                case llvm::Type::FixedVectorTyID: {
                    auto *vec_ty = llvm::cast<llvm::FixedVectorType>(type);
                    llvm::Type *elem_ty = vec_ty->getElementType();
                    type_layout elem_layout = get_type_layout<BlueprintFieldType>(elem_ty);
                    type_layout res;
                    for (size_t i = 0; i < vec_ty->getNumElements(); ++i) {
                        res.insert(res.end(), elem_layout.begin(), elem_layout.end());
                    }
                    return res;
                }
                default:
                    UNREACHABLE("Unsupported type");
                }
            }

            template<typename BlueprintFieldType>
            size_t get_cells_num(llvm::Type *type) {
                type_layout layout = get_type_layout<BlueprintFieldType>(type);
                size_t num = 0;
                for (auto &layout_pair : layout) {
                    num += 1 + layout_pair.second;
                }
                return num;
            }

            LayoutResolver(const LayoutResolver &) = delete;
            LayoutResolver(LayoutResolver &&) = delete;

        private:
            template<typename BlueprintFieldType>
            IndexMapping &resolve_type(llvm::Type *type) {
                if (type_cache.find(type) != type_cache.end()) {
                    return type_cache[type];
                }
                IndexMapping cache_data {{}, 0, 0};
                switch (type->getTypeID()) {
                case llvm::Type::IntegerTyID:
                case llvm::Type::PointerTyID:
                    cache_data.size = 1;
                    cache_data.width = get_type_size(type);
                    break;
                case llvm::Type::GaloisFieldTyID:
                    cache_data.size = field_arg_num<BlueprintFieldType>(type);
                    cache_data.width = get_type_size(type);
                    break;
                case llvm::Type::EllipticCurveTyID:
                    cache_data.size = curve_arg_num<BlueprintFieldType>(type);
                    cache_data.width = get_type_size(type);
                    break;
                case llvm::Type::ArrayTyID: {
                    auto *array_ty = llvm::cast<llvm::ArrayType>(type);
                    llvm::Type *elem_ty = array_ty->getElementType();
                    unsigned elem_size = resolve_type<BlueprintFieldType>(elem_ty).size;
                    size_t elem_width = get_type_size(elem_ty);
                    cache_data.size = array_ty->getNumElements() * elem_size;
                    cache_data.width = array_ty->getNumElements() * elem_width;
                    cache_data.indices.resize(array_ty->getNumElements());
                    for (unsigned i = 0; i < array_ty->getNumElements(); ++i) {
                        cache_data.indices[i].idx = i * elem_size;
                        cache_data.indices[i].type = elem_ty;
                        cache_data.indices[i].offset = i * elem_width;
                    }
                    break;
                }
                case llvm::Type::StructTyID: {
                    auto *struct_ty = llvm::cast<llvm::StructType>(type);

                    unsigned prev_idx = 0;
                    unsigned prev_width = 0;
                    cache_data.indices.resize(struct_ty->getNumElements());
                    for (unsigned i = 0; i < struct_ty->getNumElements(); ++i) {
                        auto elem_ty = struct_ty->getElementType(i);
                        auto &resolved_element = resolve_type<BlueprintFieldType>(elem_ty);
                        cache_data.size += resolved_element.size;
                        cache_data.width += resolved_element.width;
                        cache_data.indices[i] = {elem_ty, prev_idx, prev_width};
                        prev_idx = cache_data.size;
                        prev_width = cache_data.width;
                    }
                    break;
                }
                case llvm::Type::FixedVectorTyID: {
                    auto *vector_ty = llvm::cast<llvm::FixedVectorType>(type);
                    llvm::Type *elem_ty = vector_ty->getElementType();
                    auto &resolved_element = resolve_type<BlueprintFieldType>(elem_ty);
                    unsigned elem_size = resolved_element.size;
                    cache_data.size = vector_ty->getNumElements() * elem_size;
                    cache_data.width = vector_ty->getNumElements() * resolved_element.width;
                    break;
                }
                default:
                    UNREACHABLE("Unexpected type");
                }
                type_cache[type] = cache_data;
                return type_cache[type];
            }
            std::unordered_map<const llvm::Type *, IndexMapping> type_cache;
            const llvm::DataLayout &layout;
        };
    }
}    // namespace nil

#endif  // ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_LAYOUT_RESOLVER_HPP_
