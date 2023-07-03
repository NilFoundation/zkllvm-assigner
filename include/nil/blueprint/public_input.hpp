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
#include <boost/json/src.hpp>

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
                        UNREACHABLE("pallas curve is not supported for used native field yet");
                    }
                    return size;
                }
                case llvm::ELLIPTIC_CURVE_VESTA: {
                    size = blueprint_element_size<BlueprintFieldType>::vesta_curve_size;
                    if (size == 0) {
                        UNREACHABLE("vesta curve is not supported for used native field yet");
                    }
                    return size;
                }
                case llvm::ELLIPTIC_CURVE_CURVE25519: {
                    size = blueprint_element_size<BlueprintFieldType>::ed25519_curve_size;
                    if (size == 0) {
                        UNREACHABLE("curve25519 is not supported for used native field yet");
                    }
                    return size;
                }
                case llvm::ELLIPTIC_CURVE_BLS12381: {
                    size = blueprint_element_size<BlueprintFieldType>::bls12381_curve_size;
                    if (size == 0) {
                        UNREACHABLE("bls12381 is not supported for used native field yet");
                    }
                    return size;
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
                    size = blueprint_element_size<BlueprintFieldType>::pallas_base_size;
                    if (size == 0) {
                        UNREACHABLE("pallas base field is not supported for used native field yet");
                    }
                    return size;
                }
                case llvm::GALOIS_FIELD_PALLAS_SCALAR: {
                    size = blueprint_element_size<BlueprintFieldType>::pallas_scalar_size;
                    if (size == 0) {
                        UNREACHABLE("pallas scalar field is not supported for used native field yet");
                    }
                    return size;
                }
                case llvm::GALOIS_FIELD_VESTA_BASE: {
                    size = blueprint_element_size<BlueprintFieldType>::vesta_base_size;
                    if (size == 0) {
                        UNREACHABLE("vesta base field is not supported for used native field yet");
                    }
                    return size;
                }
                case llvm::GALOIS_FIELD_VESTA_SCALAR: {
                    size = blueprint_element_size<BlueprintFieldType>::vesta_scalar_size;
                    if (size == 0) {
                        UNREACHABLE("vesta scalar field is not supported for used native field yet");
                    }
                    return size;
                }
                case llvm::GALOIS_FIELD_BLS12381_BASE: {
                    size = blueprint_element_size<BlueprintFieldType>::bls12381_base_size;
                    if (size == 0) {
                        UNREACHABLE("bls12381 base field is not supported for used native field yet");
                    }
                    return size;
                }
                case llvm::GALOIS_FIELD_BLS12381_SCALAR: {
                    size = blueprint_element_size<BlueprintFieldType>::bls12381_scalar_size;
                    if (size == 0) {
                        UNREACHABLE("bls12381 scalar field is not supported for used native field yet");
                    }
                    return size;
                }
                case llvm::GALOIS_FIELD_CURVE25519_BASE: {
                    size = blueprint_element_size<BlueprintFieldType>::ed25519_base_size;
                    if (size == 0) {
                        UNREACHABLE("ed25519 base field is not supported for used native field yet");
                    }
                    return size;
                }
                case llvm::GALOIS_FIELD_CURVE25519_SCALAR: {
                    size = blueprint_element_size<BlueprintFieldType>::ed25519_scalar_size;
                    if (size == 0) {
                        UNREACHABLE("ed25519 scalar field is not supported for used native field yet");
                    }
                    return size;
                }

                default:
                    UNREACHABLE("unsupported field operand type");
            }
        }

        template<typename BlueprintFieldType, typename var, typename Assignment>
        class PublicInputReader {
        public:
            PublicInputReader(stack_frame<var> &frame, Assignment &assignmnt) :
                frame(frame),
                assignmnt(assignmnt), public_input_idx(0) {}

            bool parse_scalar(const boost::json::value &value, typename BlueprintFieldType::value_type &out) {
                switch (value.kind()) {
                case boost::json::kind::int64:
                    out = value.as_int64();
                    return true;
                case boost::json::kind::uint64:
                    out = value.as_uint64();
                    return true;
                case boost::json::kind::string: {
                    char buf[256];
                    if (value.as_string().size() >= sizeof(buf)) {
                        std::cerr << "Input does not fit into BlueprintFieldType" << std::endl;
                        return false;
                    }
                    value.as_string().copy(buf, sizeof(buf));
                    typename BlueprintFieldType::extended_integral_type number(buf);
                    if (number >= BlueprintFieldType::modulus) {
                        std::cerr << "Input does not fit into BlueprintFieldType" << std::endl;
                        return false;
                    }
                    out = number;
                    return true;
                }
                default:
                    return false;

                }
            }

            std::vector<var> take_values(const boost::json::value &value, size_t len) {
                std::vector<var> res(len);
                switch (value.kind()) {
                case boost::json::kind::array:
                    if (len != value.as_array().size()) {
                        return {};
                    }
                    for (size_t i = 0; i < len; ++i) {
                        if (!parse_scalar(value.as_array()[i], assignmnt.public_input(0, public_input_idx)))
                            return {};
                        auto input_var = var(0, public_input_idx++, false, var::column_type::public_input);
                        res[i] = input_var;
                    }
                    break;
                case boost::json::kind::int64:
                case boost::json::kind::uint64:
                case boost::json::kind::string:
                    if (len != 1 || !parse_scalar(value, assignmnt.public_input(0, public_input_idx))) {
                        return {};
                    }
                    res[0] = var(0, public_input_idx++, false, var::column_type::public_input);
                    break;
                default:
                    return {};
                }
                return res;
            }

            bool take_curve(llvm::Value *curve_arg, llvm::Type *curve_type, const boost::json::object &value) {
                size_t arg_len = curve_arg_num<BlueprintFieldType>(curve_type);
                ASSERT_MSG(arg_len >= 2, "arg_len of curveTy cannot be less than two");
                if (value.size() != 1 || !value.contains("curve"))
                    return false;
                frame.vectors[curve_arg] = take_values(value.at("curve"), arg_len);
                return frame.vectors[curve_arg].size() == arg_len;
            }

            bool take_field(llvm::Value *field_arg, llvm::Type *field_type, const boost::json::object &value) {
                ASSERT(llvm::isa<llvm::GaloisFieldType>(field_type));
                if (value.size() != 1 || !value.contains("field"))
                    return false;
                size_t arg_len = field_arg_num<BlueprintFieldType>(field_type);
                ASSERT_MSG(arg_len != 0, "wrong input size");
                if (value.at("field").is_double()) {
                    error =
                        "got double value for field argument. Probably the value is too big to be represented as "
                        "integer. You can put it in \"\" to avoid JSON parser restrictions.";
                }
                auto values = take_values(value.at("field"), arg_len);
                if (values.size() != arg_len)
                    return false;
                if (arg_len == 1) {
                    frame.scalars[field_arg] = values[0];
                } else {
                    frame.vectors[field_arg] = values;
                }
                return true;
            }

            bool take_int(llvm::Value *int_arg, const boost::json::object &value) {
                if (value.size() != 1 || !value.contains("int"))
                    return false;
                auto values = take_values(value.at("int"), 1);
                if (values.size() != 1)
                    return false;
                frame.scalars[int_arg] = values[0];
                return true;
            }

            bool take_vector(llvm::Value *vector_arg, llvm::Type *vector_type, const boost::json::object &value) {
                size_t arg_len = llvm::cast<llvm::FixedVectorType>(vector_type)->getNumElements();
                if (value.size() != 1 && !value.contains("vector")) {
                    return false;
                }
                frame.vectors[vector_arg] = take_values(value.at("vector"), arg_len);
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
                    ASSERT(vector_type->getElementType()->isFieldTy());
                    return vector_type->getNumElements();
                }
                UNREACHABLE("Unsupported element type!");
                return 0;
            }

            bool try_array(llvm::Value *array_arg, llvm::Type *arg_type, const boost::json::object &value) {
                auto pointee = llvm::cast<llvm::PointerType>(arg_type)->getNonOpaquePointerElementType();
                if (pointee->getNumContainedTypes() != 1 || !pointee->getContainedType(0)->isArrayTy()) {
                    return false;
                }
                auto *array_type = llvm::cast<llvm::ArrayType>(pointee->getContainedType(0));
                size_t array_len = array_type->getNumElements();
                if (array_len == 0) {
                    return false;
                }
                auto elem_type = array_type->getElementType();
                size_t elem_len = get_array_elem_len(elem_type);
                if (value.size() != 1 && !value.contains("array")) {
                    return false;
                }
                if (!value.at("array").is_array()) {
                    return false;
                }
                const auto &json_arr = value.at("array").as_array();
                if (json_arr.size() != array_len) {
                    return false;
                }

                for (int i = 0; i < array_len; ++i) {
                    std::vector<var> elem_value = take_values(json_arr[i], elem_len);
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

            bool try_string(llvm::Value *arg, llvm::Type *arg_type, const boost::json::object &value) {
                auto pointee = llvm::cast<llvm::PointerType>(arg_type)->getNonOpaquePointerElementType();
                if (!pointee->isIntegerTy(8)) {
                    return false;
                }
                if (value.size() != 1 && !value.contains("string")) {
                    return false;
                }
                if (!value.at("string").is_string()) {
                    return false;
                }
                const auto &json_str = value.at("string").as_string();
                unsigned idx = 0;
                for (char c : json_str) {
                    assignmnt.public_input(0, public_input_idx) = c;
                    auto variable = var(0, public_input_idx++, false, var::column_type::public_input);
                    frame.memory.back().store_var(variable, idx++);
                }
                // Put '\0' at the end
                assignmnt.public_input(0, public_input_idx) = 0;
                auto variable = var(0, public_input_idx++, false, var::column_type::public_input);
                frame.memory.back().store_var(variable, idx++);
                return true;
            }

            bool fill_public_input(const llvm::Function &function, const boost::json::array &public_input) {
                size_t ret_gap = 0;
                for (size_t i = 0; i < function.arg_size(); ++i) {
                    if (public_input.size() <= i - ret_gap || !public_input[i - ret_gap].is_object()) {
                        error = "not enough values in the input file.";
                        return false;
                    }

                    llvm::Argument *current_arg = function.getArg(i);
                    const boost::json::object &current_value = public_input[i - ret_gap].as_object();
                    llvm::Type *arg_type = current_arg->getType();
                    if (llvm::isa<llvm::PointerType>(arg_type)) {
                        frame.memory.emplace_back();
                        frame.pointers[current_arg] = Pointer<var>(&frame.memory.back(), 0);
                        if (current_arg->hasStructRetAttr()) {
                            // No need to fill in a return argument
                            ret_gap += 1;
                            continue;
                        }
                        if (!try_array(current_arg, arg_type, current_value) &&
                            !try_string(current_arg, arg_type, current_value)) {
                            std::cerr << "Got pointer argument, only pointers to std::array or char are supported" << std::endl;
                            return false;
                        }
                    } else if (llvm::isa<llvm::FixedVectorType>(arg_type)) {
                        if (!take_vector(current_arg, arg_type, current_value))
                            return false;
                    } else if (llvm::isa<llvm::EllipticCurveType>(arg_type)) {
                        if (!take_curve(current_arg, arg_type, current_value))
                            return false;
                    } else if (llvm::isa<llvm::GaloisFieldType>(arg_type)) {
                        if (!take_field(current_arg, arg_type, current_value))
                            return false;
                    } else if (llvm::isa<llvm::IntegerType>(arg_type)) {
                        if (!take_int(current_arg, current_value))
                            return false;
                    }
                    else {
                        UNREACHABLE("unsupported input type");
                    }
                }

                // Check if there are remaining elements of public input
                if (function.arg_size() - ret_gap != public_input.size()) {
                    error = "too many values in the input file";
                    return false;
                }
                return true;
            }
            size_t get_idx() const {
                return public_input_idx;
            }

            const std::string &get_error() const {
                return error;
            }

        private:
            stack_frame<var> &frame;
            Assignment &assignmnt;
            size_t public_input_idx;
            std::string error;
        };
    }    // namespace blueprint
}    // namespace nil


#endif  // CRYPTO3_ASSIGNER_PUBLIC_INPUT_HPP
