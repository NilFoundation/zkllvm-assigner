//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ASSIGNER_PUBLIC_INPUT_HPP
#define CRYPTO3_ASSIGNER_PUBLIC_INPUT_HPP

#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Type.h"

#include "nil/crypto3/algebra/fields/pallas/base_field.hpp"
#include <nil/blueprint/stack.hpp>

#include <iostream>

namespace nil {
    namespace blueprint {

        static unsigned getStdArrayLen(const llvm::Type *arg_type) {
            auto pointee = llvm::cast<llvm::PointerType>(arg_type)->getNonOpaquePointerElementType();
            if (pointee->getNumContainedTypes() == 1 && pointee->getContainedType(0)->isArrayTy()) {
                return llvm::cast<llvm::ArrayType>(pointee->getContainedType(0))->getNumElements();
            }
            return 0;
        }

        template<typename BlueprintFieldType>
        struct blueprint_element_size;

        template<>
        struct blueprint_element_size<typename nil::crypto3::algebra::fields::pallas_base_field> {
            constexpr static const std::size_t pallas_curve_size = 2;
            constexpr static const std::size_t vesta_curve_size = 2;
            constexpr static const std::size_t ed25519_curve_size = 0;
            constexpr static const std::size_t bls12381_curve_size = 0;

            constexpr static const std::size_t pallas_base_size = 1;
            constexpr static const std::size_t pallas_scalar_size = 2;
            constexpr static const std::size_t vesta_base_size = 0;
            constexpr static const std::size_t vesta_scalar_size = 0;
            constexpr static const std::size_t bls12381_base_size = 0;
            constexpr static const std::size_t bls12381_scalar_size = 0;
            constexpr static const std::size_t ed25519_base_size = 4;
            constexpr static const std::size_t ed25519_scalar_size = 0;
        };

        template<typename BlueprintFieldType>
        std::size_t curve_arg_num(llvm::Type *arg_type) {
            std::size_t size = 0;

            switch (llvm::cast<llvm::EllipticCurveType>(arg_type)->getCurveKind()) {
                case llvm::ELLIPTIC_CURVE_PALLAS: {
                    size = blueprint_element_size<BlueprintFieldType>::pallas_curve_size;
                    if (size == 0) {
                        std::cerr << "pallas curve is not supported for used native field yet" << std::endl;
                        assert(1 == 0 && "pallas curve is not supported for used native field yet");
                    }
                    return size;
                }
                case llvm::ELLIPTIC_CURVE_VESTA: {
                    size = blueprint_element_size<BlueprintFieldType>::vesta_curve_size;
                    if (size == 0) {
                        std::cerr << "vesta curve is not supported for used native field yet" << std::endl;
                        assert(1 == 0 && "vesta curve is not supported for used native field yet");
                    }
                    return size;
                }
                case llvm::ELLIPTIC_CURVE_CURVE25519: {
                    size = blueprint_element_size<BlueprintFieldType>::ed25519_curve_size;
                    if (size == 0) {
                        std::cerr << "curve25519 is not supported for used native field yet" << std::endl;
                        assert(1 == 0 && "curve25519 is not supported for used native field yet");
                    }
                    return size;
                }
                case llvm::ELLIPTIC_CURVE_BLS12381: {
                    size = blueprint_element_size<BlueprintFieldType>::bls12381_curve_size;
                    if (size == 0) {
                        std::cerr << "bls12381 is not supported for used native field yet" << std::endl;
                        assert(1 == 0 && "bls12381 is not supported for used native field yet");
                    }
                    return size;
                }
                default:
                    assert(1 == 0 && "unsupported curve type");
                    return 0;
            };
        }

        template<typename BlueprintFieldType>
        std::size_t field_arg_num(llvm::Type *arg_type) {
            std::size_t size = 0;
            switch (llvm::cast<llvm::GaloisFieldType>(arg_type)->getFieldKind()) {
                case llvm::GALOIS_FIELD_PALLAS_BASE: {
                    size = blueprint_element_size<BlueprintFieldType>::pallas_base_size;
                    if (size == 0) {
                        std::cerr << "pallas base field is not supported for used native field yet" << std::endl;
                        assert(1 == 0 && "pallas base field is not supported for used native field yet");
                    }
                    return size;
                }
                case llvm::GALOIS_FIELD_PALLAS_SCALAR: {
                    size = blueprint_element_size<BlueprintFieldType>::pallas_scalar_size;
                    if (size == 0) {
                        std::cerr <<  "pallas scalar field is not supported for used native field yet" << std::endl;
                        assert(1 == 0 && "pallas scalar field is not supported for used native field yet");
                    }
                    return size;
                }
                case llvm::GALOIS_FIELD_VESTA_BASE: {
                    size = blueprint_element_size<BlueprintFieldType>::vesta_base_size;
                    if (size == 0) {
                        std::cerr <<  "vesta base field is not supported for used native field yet" << std::endl;
                        assert(1 == 0 && "vesta base field is not supported for used native field yet");
                    }
                    return size;
                }
                case llvm::GALOIS_FIELD_VESTA_SCALAR: {
                    size = blueprint_element_size<BlueprintFieldType>::vesta_scalar_size;
                    if (size == 0) {
                        std::cerr <<  "vesta scalar field is not supported for used native field yet" << std::endl;
                        assert(1 == 0 && "vesta scalar field is not supported for used native field yet");
                    }
                    return size;
                }
                case llvm::GALOIS_FIELD_BLS12381_BASE: {
                    size = blueprint_element_size<BlueprintFieldType>::bls12381_base_size;
                    if (size == 0) {
                        std::cerr <<  "bls12381 base field is not supported for used native field yet" << std::endl;
                        assert(1 == 0 && "bls12381 base field is not supported for used native field yet");
                    }
                    return size;
                }
                case llvm::GALOIS_FIELD_BLS12381_SCALAR: {
                    size = blueprint_element_size<BlueprintFieldType>::bls12381_scalar_size;
                    if (size == 0) {
                        std::cerr << "bls12381 scalar field is not supported for used native field yet" << std::endl;
                        assert(1 == 0 && "bls12381 scalar field is not supported for used native field yet");
                    }
                    return size;
                }
                case llvm::GALOIS_FIELD_CURVE25519_BASE: {
                    size = blueprint_element_size<BlueprintFieldType>::ed25519_base_size;
                    if (size == 0) {
                        std::cerr << "ed25519 base field is not supported for used native field yet" << std::endl;
                        assert(1 == 0 && "ed25519 base field is not supported for used native field yet");
                    }
                    return size;
                }
                case llvm::GALOIS_FIELD_CURVE25519_SCALAR: {
                    size = blueprint_element_size<BlueprintFieldType>::ed25519_scalar_size;
                    if (size == 0) {
                        std::cerr << "ed25519 scalar field is not supported for used native field yet" << std::endl;
                        assert(1 == 0 && "ed25519 scalar field is not supported for used native field yet");
                    }
                    return size;
                }

                default:
                    assert(1 == 0 && "unsupported field operand type");
            }
        }

        template<typename BlueprintFieldType, typename var, typename Assignment, typename PublicInputContainerType>
        class PublicInputReader {
        public:
            PublicInputReader(stack_frame<var> &frame, Assignment &assignmnt,
                              const PublicInputContainerType &public_input) :
                frame(frame),
                assignmnt(assignmnt), public_input(public_input), public_input_idx(0) {}

            std::vector<var> take_values(size_t len) {
                if (len + public_input_idx > public_input.size()) {
                    return {};
                }
                std::vector<var> res(len);
                for (size_t i = 0; i < len; ++i) {
                    assignmnt.public_input(0, public_input_idx) = public_input[public_input_idx];
                    auto input_var = var(0, public_input_idx++, false, var::column_type::public_input);
                    res[i] = input_var;
                }
                return res;
            }

            bool take_curve(llvm::Value *curve_arg, llvm::Type *curve_type) {
                size_t arg_len = curve_arg_num<BlueprintFieldType>(curve_type);
                assert(arg_len >= 2 && "arg_len of curveTy cannot be less than two");
                frame.vectors[curve_arg] = take_values(arg_len);
                return frame.vectors[curve_arg].size() == arg_len;
            }

            bool take_field(llvm::Value *field_arg, llvm::Type *field_type) {
                assert(llvm::isa<llvm::GaloisFieldType>(field_type));
                size_t arg_len = field_arg_num<BlueprintFieldType>(field_type);
                assert(arg_len != 0 && "wrong input size");
                auto values = take_values(arg_len);
                if (values.size() != arg_len)
                    return false;
                if (arg_len == 1) {
                    frame.scalars[field_arg] = values[0];
                } else {
                    frame.vectors[field_arg] = values;
                }
                return true;
            }

            bool take_vector(llvm::Value *vector_arg, llvm::Type *vector_type) {
                size_t arg_len = llvm::cast<llvm::FixedVectorType>(vector_type)->getNumElements();
                frame.vectors[vector_arg] = take_values(arg_len);
                return frame.vectors[vector_arg].size() == arg_len;
            }

            size_t get_array_elem_len(llvm::Type *elem_type) {
                if (elem_type->isFieldTy()) {
                    return field_arg_num<BlueprintFieldType>(elem_type);
                }
                if (elem_type->isCurveTy()) {
                    return curve_arg_num<BlueprintFieldType>(elem_type);
                }
                if (auto vector_type = llvm::dyn_cast<llvm::FixedVectorType>(elem_type)) {
                    assert(vector_type->getElementType()->isFieldTy());
                    return vector_type->getNumElements();
                }
                assert(false && "Unsupported element type!");
                return 0;
            }

            bool take_array(llvm::Value *array_arg, llvm::Type *array_type, size_t array_len) {
                auto elem_type = llvm::cast<llvm::ArrayType>(llvm::cast<llvm::PointerType>(array_type)
                                                                 ->getNonOpaquePointerElementType()
                                                                 ->getContainedType(0))
                                     ->getElementType();
                size_t elem_len = get_array_elem_len(elem_type);
                for (int i = 0; i < array_len; ++i) {
                    std::vector<var> elem_value = take_values(elem_len);
                    if (elem_value.size() != elem_len)
                        return false;
                    if (elem_len == 1) {
                        frame.memory.back().store_var(elem_value[0], i);
                    } else {
                        frame.memory.back().store_vector(elem_value, i);
                    }
                }
                return true;
            }

            bool fill_public_input(const llvm::Function &function) {
                for (size_t i = 0; i < function.arg_size(); ++i) {
                    if (public_input_idx >= public_input.size()) {
                        return false;
                    }
                    llvm::Argument *current_arg = function.getArg(i);
                    llvm::Type *arg_type = current_arg->getType();
                    bool is_array = false;
                    unsigned arg_len = 0;
                    if (llvm::isa<llvm::PointerType>(arg_type)) {
                        frame.memory.emplace_back();
                        frame.pointers[current_arg] = Pointer<var>(&frame.memory.back(), 0);
                        arg_len = getStdArrayLen(arg_type);
                        if (arg_len == 0) {
                            std::cerr << "Got pointer argument, only pointers to std::array are supported" << std::endl;
                            return false;
                        }
                        is_array = true;
                        if (current_arg->hasStructRetAttr()) {
                            // No need to fill in a return argument
                            continue;
                        }

                        if (!take_array(current_arg, arg_type, arg_len))
                            return false;
                    } else if (llvm::isa<llvm::FixedVectorType>(arg_type)) {
                        if (!take_vector(current_arg, arg_type))
                            return false;
                    } else if (llvm::isa<llvm::EllipticCurveType>(arg_type)) {
                        if (!take_curve(current_arg, arg_type))
                            return false;
                    } else if (llvm::isa<llvm::GaloisFieldType>(arg_type)) {
                        if (!take_field(current_arg, arg_type))
                            return false;
                    }
                    else {
                        assert(1==0 && "unsupported input type");
                    }
                }
                if (public_input_idx != public_input.size()) {
                    return false;
                }
                return true;
            }

        private:
            stack_frame<var> &frame;
            Assignment &assignmnt;
            const PublicInputContainerType &public_input;
            size_t public_input_idx;
        };
    }    // namespace blueprint
}    // namespace nil


#endif  // CRYPTO3_ASSIGNER_PUBLIC_INPUT_HPP
