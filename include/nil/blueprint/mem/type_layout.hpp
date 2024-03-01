//---------------------------------------------------------------------------//
// Copyright (c) 2023 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2023 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2023 Mikhail Aksenov <maksenov@nil.foundation>
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
// @file This file defines how LLVM types are represented in assigner memory.
//---------------------------------------------------------------------------//

#ifndef ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_MEM_TYPE_LAYOUT_HPP_
#define ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_MEM_TYPE_LAYOUT_HPP_

#include "nil/blueprint/mem/layout.hpp"

#include "nil/blueprint/asserts.hpp"
#include "nil/blueprint/macros.hpp"
#include "nil/blueprint/non_native_marshalling.hpp"

#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"

#include <vector>
#include <list>

namespace nil {
    namespace blueprint {
        namespace mem {
            /**
             * @brief This class designed to handle all type layout calculcations: sizes and offsets of types.
             * It is aligned with assigner memory model in terms of representing scalar and compound types.
             * This class is actually the one who defines, what does native Galois field means.
             * All the size and offset calculations should be done through this class, instead of
             * calling directly to LLVM.
             *
             * @tparam BlueprintFieldType type of native field, which affects layouts of all field and curve types.
             */
            class TypeLayoutResolver {
            public:
                /**
                 * @brief Sizes of scalar components of a type.
                 *
                 * Scalar types in assigner memory are the following:
                 *  - integers
                 *  - pointer
                 *  - native fields
                 *
                 * Each of this types must be stored in a single segment of memory.
                 *
                 * This type is a flat representation of a type with the sizes of all single value types
                 * in a type. E.g. for struct type `{ i32, { i64, ptr }, <2 x i8> }` the layout will be
                 * `{ 4, 8, 8, 1, 1 }`.
                 *
                 * Another important notice: all alignments in assigner memory are ignored and equals to 1.
                 * This means that for any type `T` its size must be equal to sum of its layout.
                 */
                using type_layout = std::vector<size_type>;

                TypeLayoutResolver(const llvm::DataLayout &layout) : layout(layout) {
                }

                /**
                 * @brief Calculate relative offset for element of an aggregate type, specified by indices.
                 *
                 * E.g. given a type `{ i32, [4 x i32] }` and indices `[1, 2]`, offset is 8.
                 *
                 * @param type aggregate type (struct or array)
                 * @param indices list of indices defining inner element of type. Take a note that
                 * this function modifies this list, passed by reference. At the end of calculcations
                 * this list will be empty.
                 */
                size_type get_offset_of_element(llvm::Type *type, std::list<int> &indices) {
                    ASSERT(type->isAggregateType());
                    // We recursively handle all "nesting levels". Levels are matching to indices:
                    // each index defines offset on a certain nesting level.
                    if (indices.empty()) {
                        // No matter the type, the offset will be 0 withour indices.
                        return 0;
                    }
                    int idx = indices.front();
                    if (idx < 0) {
                        TODO("negative index of element");
                    }
                    indices.pop_front();
                    size_type offset = 0;
                    llvm::Type *nested_type;
                    if (llvm::StructType *struct_ty = llvm::dyn_cast<llvm::StructType>(type)) {
                        // For struct type we sum up sizes of all fields before `idx`
                        for (unsigned i = 0; i < idx; ++i) {
                            offset += get_type_size(struct_ty->getStructElementType(i));
                        }
                        nested_type = struct_ty->getStructElementType(idx);
                    } else if (llvm::ArrayType *array_ty = llvm::dyn_cast<llvm::ArrayType>(type)) {
                        // For array type we don't need to calculate element sizes one by one, because
                        // they all have the same size. So just multiply it by number of elements.
                        offset = idx * get_type_size(array_ty->getArrayElementType());
                        nested_type = array_ty->getArrayElementType();
                    } else {
                        // This is unreachable due to assertion above
                        UNREACHABLE("");
                    }
                    // Now go recursively deeper into nested type and handle left indices there
                    if (!indices.empty()) {
                        offset += get_offset_of_element(nested_type, indices);
                    }
                    return offset;
                }

                /// @brief Get size of type in bytes used in memory.
                size_type get_type_size(llvm::Type *type) const {
                    return layout.getTypeStoreSize(type);
                }

                /**
                 * @brief Get layout of type. See docs for `type_layout` for more info.
                 *
                 * @tparam BlueprintFieldType type of native field
                 */
                template<typename BlueprintFieldType>
                type_layout get_type_layout(llvm::Type *type) {
                    switch (type->getTypeID()) {
                        case llvm::Type::IntegerTyID:
                        case llvm::Type::PointerTyID:
                            return {get_type_size(type)};
                        case llvm::Type::GaloisFieldTyID: {
                            std::size_t chunks_num = field_arg_num<BlueprintFieldType>(type);
                            // Chunks of a marshalled non-native field has equal segment size.
                            // Total size of field is "splitted equally" among them.
                            return type_layout(chunks_num, get_type_size(type) / chunks_num);
                        }
                        case llvm::Type::EllipticCurveTyID: {
                            std::size_t chunks_num = curve_arg_num<BlueprintFieldType>(type);
                            // The same as with non-native fields (see comment for GaloisFieldTyID case).
                            return type_layout(chunks_num, get_type_size(type) / chunks_num);
                        }
                        case llvm::Type::StructTyID: {
                            auto *struct_ty = llvm::cast<llvm::StructType>(type);
                            type_layout res;
                            for (size_t i = 0; i < struct_ty->getNumElements(); ++i) {
                                llvm::Type *elem_ty = struct_ty->getElementType(i);
                                type_layout elem_layout = get_type_layout<BlueprintFieldType>(elem_ty);
                                res.insert(res.end(), elem_layout.begin(), elem_layout.end());
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
                            LLVM_PRINT(type, str);
                            UNREACHABLE("Unknown layout of type: " + str);
                    }
                }

                TypeLayoutResolver(const TypeLayoutResolver &) = delete;
                TypeLayoutResolver(TypeLayoutResolver &&) = delete;

                const llvm::DataLayout &layout;

                // TODO: probably we should add caching here to optimize retrieving layouts and offsets.
                // TODO: probably it's good idea to get rid of template parameter of this class and switch to
                // constant parameter of type llvm::GaloisFieldKind.
            };
        }    // namespace mem
    }    // namespace blueprint
}    // namespace nil

#endif    // ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_MEM_TYPE_LAYOUT_HPP_
