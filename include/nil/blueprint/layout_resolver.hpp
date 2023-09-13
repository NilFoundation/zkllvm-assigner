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
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/GlobalVariable.h"

#include <nil/blueprint/basic_non_native_policy.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/ed25519.hpp>

#include "nil/crypto3/algebra/fields/pallas/base_field.hpp"

#include <nil/blueprint/asserts.hpp>

template<typename BlueprintFieldType>
        std::size_t curve_arg_num(llvm::Type *arg_type) {
            std::size_t size = 0;

            switch (llvm::cast<llvm::EllipticCurveType>(arg_type)->getCurveKind()) {
                case llvm::ELLIPTIC_CURVE_PALLAS: {
                    return 2;
                }
                case llvm::ELLIPTIC_CURVE_VESTA: {
                    UNREACHABLE("vesta curve is not supported for used native field yet");
                }
                case llvm::ELLIPTIC_CURVE_CURVE25519: {
                    return 2 * nil::blueprint::detail::basic_non_native_policy_field_type<BlueprintFieldType, typename nil::crypto3::algebra::curves::ed25519::base_field_type>::ratio;
                }
                case llvm::ELLIPTIC_CURVE_BLS12381: {
                    UNREACHABLE("bls12381 is not supported for used native field yet");
                }
                default:
                    UNREACHABLE("unsupported curve type");
                    return 0;
            };
        }

        template<typename BlueprintFieldType>
        std::size_t field_arg_num(llvm::Type *arg_type) {
            std::size_t size = 0;
            switch (llvm::cast<llvm::GaloisFieldType>(arg_type)->getFieldKind()) {
                case llvm::GALOIS_FIELD_PALLAS_BASE: {
                    return 1;
                }
                case llvm::GALOIS_FIELD_PALLAS_SCALAR: {
                    return nil::blueprint::detail::basic_non_native_policy_field_type<BlueprintFieldType, typename nil::crypto3::algebra::curves::pallas::scalar_field_type>::ratio;
                }
                case llvm::GALOIS_FIELD_VESTA_BASE: {
                    UNREACHABLE("vesta base field is not supported for used native field yet");
                }
                case llvm::GALOIS_FIELD_VESTA_SCALAR: {
                    UNREACHABLE("vesta scalar field is not supported for used native field yet");
                }
                case llvm::GALOIS_FIELD_BLS12381_BASE: {
                    UNREACHABLE("bls12381 base field is not supported for used native field yet");
                }
                case llvm::GALOIS_FIELD_BLS12381_SCALAR: {
                    UNREACHABLE("bls12381 scalar field is not supported for used native field yet");
                }
                case llvm::GALOIS_FIELD_CURVE25519_BASE: {
                    return nil::blueprint::detail::basic_non_native_policy_field_type<BlueprintFieldType, typename nil::crypto3::algebra::curves::ed25519::base_field_type>::ratio;
                }
                case llvm::GALOIS_FIELD_CURVE25519_SCALAR: {
                    return nil::blueprint::detail::basic_non_native_policy_field_type<BlueprintFieldType, typename nil::crypto3::algebra::curves::ed25519::scalar_field_type>::ratio;
                }

                default:
                    UNREACHABLE("unsupported field operand type");
            }
        }

namespace nil {
    namespace blueprint {
        // This class is intended to compute flat offsets for GEP instruction
        // to put elements of struct/array into a chunk with a correct index.
        // For example, if we have a type { i32, [2 x i32], %pointer* }
        // and the GEP instruction retrieves a pointer element (with index 2 inside the struct),
        // the answer must be 3, because we have a complex field with size 2 at the index 1
        class LayoutResolver {
            struct Element {
                const llvm::Type *type;
                unsigned idx;
            };
            struct IndexMapping {
                std::vector<Element> indices;
                unsigned size;
            };

        public:
            LayoutResolver(const llvm::DataLayout &layout): layout(layout) {}
            template <typename BlueprintFieldType, typename Array>
            int get_flat_index(llvm::Type *type, const Array &gep_indices) {
                ASSERT(type->isAggregateType());
                if (type_cache.find(type) == type_cache.end())
                    resolve_type<BlueprintFieldType>(type);
                auto *type_record = &type_cache[type];
                for (unsigned i = 0; i < gep_indices.size() - 1; ++i) {
                    type_record = &type_cache[type_record->indices[gep_indices[i]].type];
                }
                return type_record->indices[gep_indices.back()].idx;
            }

            unsigned get_type_size(llvm::Type *type) {
                return layout.getTypeStoreSize(type);
            }

            template <typename BlueprintFieldType>
            std::vector<unsigned> get_type_layout(llvm::Type *type) {
                // TODO(maksenov): add type cache
                switch (type->getTypeID()) {
                case llvm::Type::IntegerTyID:
                case llvm::Type::PointerTyID:
                    return {get_type_size(type)};
                case llvm::Type::GaloisFieldTyID: {
                    std::vector<unsigned> res;
                    res.push_back(get_type_size(type));
                    for (int i = 1; i < field_arg_num<BlueprintFieldType>(type); ++i) {
                        res.push_back(0);
                    }
                    return res;
                }
                case llvm::Type::EllipticCurveTyID: {
                    std::vector<unsigned> res;
                    res.push_back(get_type_size(type));
                    for (int i = 1; i < curve_arg_num<BlueprintFieldType>(type); ++i) {
                        res.push_back(0);
                    }
                    return res;
                }
                case llvm::Type::StructTyID: {
                    auto *struct_ty = llvm::cast<llvm::StructType>(type);
                    std::vector<unsigned> res;
                    for (size_t i = 0; i < struct_ty->getNumElements(); ++i) {
                        auto offf = get_type_layout<BlueprintFieldType>(struct_ty->getElementType(i));
                        res.insert(res.end(), offf.begin(), offf.end());
                    }
                    return res;
                }
                case llvm::Type::ArrayTyID: {
                    auto *array_ty = llvm::cast<llvm::ArrayType>(type);
                    llvm::Type *elem_ty = array_ty->getElementType();
                    std::vector<unsigned> elem_layout = get_type_layout<BlueprintFieldType>(elem_ty);
                    std::vector<unsigned> res;
                    for (size_t i = 0; i < array_ty->getNumElements(); ++i) {
                        res.insert(res.end(), elem_layout.begin(), elem_layout.end());
                    }
                    return res;
                }
                case llvm::Type::FixedVectorTyID: {
                    auto *vec_ty = llvm::cast<llvm::FixedVectorType>(type);
                    llvm::Type *elem_ty = vec_ty->getElementType();
                    std::vector<unsigned> elem_layout = get_type_layout<BlueprintFieldType>(elem_ty);
                    std::vector<unsigned> res;
                    for (size_t i = 0; i < vec_ty->getNumElements(); ++i) {
                        res.insert(res.end(), elem_layout.begin(), elem_layout.end());
                    }
                    return res;
                }
                default:
                    UNREACHABLE("Unsupported type");
                }
            }

            LayoutResolver(const LayoutResolver &) = delete;
            LayoutResolver(LayoutResolver &&) = delete;

        private:
            template<typename BlueprintFieldType>
            unsigned resolve_type(llvm::Type *type) {
                if (type_cache.find(type) != type_cache.end()) {
                    return type_cache[type].size;
                }
                IndexMapping cache_data {{}, 0};
                switch (type->getTypeID()) {
                case llvm::Type::IntegerTyID:
                case llvm::Type::PointerTyID:
                    return 1;
                case llvm::Type::GaloisFieldTyID:
                    return field_arg_num<BlueprintFieldType>(type);
                case llvm::Type::EllipticCurveTyID:
                    return curve_arg_num<BlueprintFieldType>(type);
                case llvm::Type::ArrayTyID: {
                    auto *array_ty = llvm::cast<llvm::ArrayType>(type);
                    llvm::Type *elem_ty = array_ty->getElementType();
                    unsigned elem_size = resolve_type<BlueprintFieldType>(elem_ty);
                    cache_data.size = array_ty->getNumElements() * elem_size;
                    cache_data.indices.resize(array_ty->getNumElements());
                    for (unsigned i = 0; i < array_ty->getNumElements(); ++i) {
                        cache_data.indices[i].idx = i * elem_size;
                        cache_data.indices[i].type = elem_ty;
                    }
                    type_cache[type] = cache_data;
                    return cache_data.size;
                }
                case llvm::Type::StructTyID: {
                    auto *struct_ty = llvm::cast<llvm::StructType>(type);

                    unsigned prev = 0;
                    cache_data.indices.resize(struct_ty->getNumElements());
                    for (unsigned i = 0; i < struct_ty->getNumElements(); ++i) {
                        auto elem_ty = struct_ty->getElementType(i);
                        cache_data.size += resolve_type<BlueprintFieldType>(elem_ty);
                        cache_data.indices[i] = {elem_ty,prev};
                        prev = cache_data.size;
                    }
                    type_cache[type] = cache_data;
                    return cache_data.size;
                }
                case llvm::Type::FixedVectorTyID: {
                    auto *vector_ty = llvm::cast<llvm::FixedVectorType>(type);
                    llvm::Type *elem_ty = vector_ty->getElementType();
                    unsigned elem_size = resolve_type<BlueprintFieldType>(elem_ty);
                    return vector_ty->getNumElements() * elem_size;
                }
                default:
                    UNREACHABLE("Unexpected type");
                }
            }
            std::unordered_map<const llvm::Type *, IndexMapping> type_cache;
            const llvm::DataLayout &layout;
        };
    }
}    // namespace nil

#endif  // CRYPTO3_ASSIGNER_GEP_RESOLVER_HPP
