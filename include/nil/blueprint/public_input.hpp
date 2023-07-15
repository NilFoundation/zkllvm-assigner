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

#include <nil/blueprint/basic_non_native_policy.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/ed25519.hpp>

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

        template<typename BlueprintFieldType>
        std::vector<typename BlueprintFieldType::value_type> extended_integral_into_vector (llvm::GaloisFieldKind arg_field_type, typename BlueprintFieldType::extended_integral_type glued_non_native) {

            switch (arg_field_type) {
                case llvm::GALOIS_FIELD_CURVE25519_BASE: {
                    using non_native_field_type = typename nil::crypto3::algebra::curves::ed25519::base_field_type;
                    using non_native_policy = typename nil::blueprint::detail::basic_non_native_policy_field_type<BlueprintFieldType, non_native_field_type>;
                    if(glued_non_native >= non_native_field_type::modulus) {
                        std::cerr << std::hex;
                        std::cerr << "0x" << glued_non_native << " >=\n";
                        std::cerr << "0x" << non_native_field_type::modulus << "\n";
                        UNREACHABLE("value does not fit into ed25519 base field!");
                    }
                    auto res = non_native_policy::chop_non_native(glued_non_native);
                    std::vector<typename BlueprintFieldType::value_type> result;
                    for (std::size_t i = 0; i < res.size(); i++) {
                        result.push_back(res[i]);
                    }
                    return result;
                }
                case llvm::GALOIS_FIELD_CURVE25519_SCALAR: {
                    using non_native_field_type = typename nil::crypto3::algebra::curves::ed25519::scalar_field_type;
                    using non_native_policy = typename nil::blueprint::detail::basic_non_native_policy_field_type<BlueprintFieldType, non_native_field_type>;
                    if(glued_non_native >= non_native_field_type::modulus) {
                        std::cerr << std::hex;
                        std::cerr << "0x" << glued_non_native << " >=\n";
                        std::cerr << "0x" << non_native_field_type::modulus << "\n";
                        UNREACHABLE("value does not fit into ed25519 scalar field!");
                    }
                    if (nil::blueprint::detail::basic_non_native_policy_field_type<BlueprintFieldType, typename nil::crypto3::algebra::curves::ed25519::scalar_field_type>::ratio != 1) {
                        UNREACHABLE("ed25519 scalar field size must be 1 for used BlueprintFieldType");
                    }
                    std::vector<typename BlueprintFieldType::value_type> result;
                    result.push_back(glued_non_native);
                    return result;
                }
                case llvm::GALOIS_FIELD_PALLAS_BASE: {
                    if(glued_non_native >= BlueprintFieldType::modulus) {
                        std::cerr << std::hex;
                        std::cerr << "0x" << glued_non_native << " >=\n";
                        std::cerr << "0x" << BlueprintFieldType::modulus << "\n";
                        UNREACHABLE("value does not fit into pallas base field!");
                    }
                    if (nil::blueprint::detail::basic_non_native_policy_field_type<BlueprintFieldType, typename nil::crypto3::algebra::curves::pallas::base_field_type>::ratio != 1) {
                        UNREACHABLE("pallas base field size must be 1 for used BlueprintFieldType");
                    }
                    std::vector<typename BlueprintFieldType::value_type> result;
                    result.push_back(glued_non_native);
                    return result;
                }
                case llvm::GALOIS_FIELD_PALLAS_SCALAR: {
                    using non_native_field_type = typename nil::crypto3::algebra::curves::pallas::scalar_field_type;
                    using non_native_policy = typename nil::blueprint::detail::basic_non_native_policy_field_type<BlueprintFieldType, non_native_field_type>;
                    if(glued_non_native >= non_native_field_type::modulus) {
                        std::cerr << std::hex;
                        std::cerr << "0x" << glued_non_native << " >=\n";
                        std::cerr << "0x" << non_native_field_type::modulus << "\n";
                        UNREACHABLE("value does not fit into pallas scalar field!");
                    }
                    auto res = non_native_policy::chop_non_native(glued_non_native);
                    std::vector<typename BlueprintFieldType::value_type> result;
                    for (std::size_t i = 0; i < res.size(); i++) {
                        result.push_back(res[i]);
                    }
                    return result;
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
                const std::size_t buflen = 256;
                char buf[buflen];
                std::size_t numlen = 0;

                switch (value.kind()) {
                case boost::json::kind::int64:
                    out = value.as_int64();
                    return true;
                case boost::json::kind::uint64:
                    out = value.as_uint64();
                    return true;
                case boost::json::kind::string: {
                    numlen = value.as_string().size();
                    if (numlen > buflen - 1) {
                        std::cerr << "value " << value.as_string() << " exceeds buffer size (" << buflen - 1 << ")\n";
                        UNREACHABLE("value size exceeds buffer size"); 
                    }
                    value.as_string().copy(buf, numlen);
                    buf[numlen] = '\0';
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

            std::vector<var> process_curve (llvm::Type *curve_type, const boost::json::object &value) {
                size_t arg_len = curve_arg_num<BlueprintFieldType>(curve_type);
                ASSERT_MSG(arg_len >= 2, "arg_len of curveTy cannot be less than two");
                if (value.size() != 1 || !value.contains("curve"))
                    UNREACHABLE("value.size() != 1 || !value.contains(\"curve\")");
                ASSERT_MSG(value.at("curve").is_array(), "curve element must be array!");
                ASSERT_MSG((value.at("curve").as_array().size() == 2), "curve element consists of two field elements!");

                llvm::GaloisFieldKind arg_field_type;
                if (llvm::isa<llvm::EllipticCurveType>(curve_type)) {
                    arg_field_type  = llvm::cast<llvm::EllipticCurveType>(curve_type)->GetBaseFieldKind();
                }
                else {UNREACHABLE("public input reader take_curve can handle only curves");}

                std::vector<var> vector1 = process_non_native_field (value.at("curve").as_array()[0], arg_field_type);
                std::vector<var> vector2 = process_non_native_field (value.at("curve").as_array()[1], arg_field_type);
                vector1.insert(vector1.end(), vector2.begin(), vector2.end());
                return vector1;
            }

            bool take_curve(llvm::Value *curve_arg, llvm::Type *curve_type, const boost::json::object &value) {
                frame.vectors[curve_arg] = process_curve(curve_type, value);
                return true;
            }

            std::vector<var> put_field_into_assignmnt (std::vector<typename BlueprintFieldType::value_type> input) {

                std::vector<var> res; 

                for (std::size_t i = 0; i < input.size(); i++) {
                    assignmnt.public_input(0, public_input_idx) = input[i];
                    res.push_back(var(0, public_input_idx++, false, var::column_type::public_input));
                }

                return res;
            }

            std::vector<var> process_non_native_field (const boost::json::value &value, llvm::GaloisFieldKind arg_field_type) {
                std::vector<var> res;
                std::vector<typename BlueprintFieldType::value_type> chunked_non_native_field_element;
                typename BlueprintFieldType::extended_integral_type non_native_number;

                const std::size_t buflen = 256;
                char buf[buflen];
                std::size_t numlen = 0;

                switch (value.kind()) {
                case boost::json::kind::int64:
                    non_native_number = typename BlueprintFieldType::extended_integral_type(value.as_int64());
                    chunked_non_native_field_element = extended_integral_into_vector<BlueprintFieldType> (arg_field_type, non_native_number);
                    res = put_field_into_assignmnt(chunked_non_native_field_element);
                    return res;
                    break;

                case boost::json::kind::uint64:
                    non_native_number = typename BlueprintFieldType::extended_integral_type(value.as_uint64());
                    chunked_non_native_field_element = extended_integral_into_vector<BlueprintFieldType> (arg_field_type, non_native_number);
                    res = put_field_into_assignmnt(chunked_non_native_field_element);
                    return res;
                    break;

                case boost::json::kind::string:
                    numlen = value.as_string().size();
                    if (numlen > buflen - 1) {
                        std::cerr << "value " << value.as_string() << " exceeds buffer size (" << buflen - 1 << ")\n";
                        UNREACHABLE("value size exceeds buffer size"); 
                    }
                    value.as_string().copy(buf, numlen);
                    buf[numlen] = '\0';
                    non_native_number = typename BlueprintFieldType::extended_integral_type(buf);

                    chunked_non_native_field_element = extended_integral_into_vector<BlueprintFieldType> (arg_field_type, non_native_number);

                    res = put_field_into_assignmnt(chunked_non_native_field_element);
                    return res;
                    break;
                default:
                    return {};
                }
            }

            std::vector<var> process_field (llvm::Type *field_type, const boost::json::object &value) {
                ASSERT(llvm::isa<llvm::GaloisFieldType>(field_type));
                if (value.size() != 1 || !value.contains("field")){
                    UNREACHABLE("value.size() != 1 || !value.contains(\"field\")");
                }
                size_t arg_len = field_arg_num<BlueprintFieldType>(field_type);
                ASSERT_MSG(arg_len != 0, "wrong input size");
                llvm::GaloisFieldKind arg_field_type;
                if (llvm::isa<llvm::GaloisFieldType>(field_type)) {
                    arg_field_type = llvm::cast<llvm::GaloisFieldType>(field_type)->getFieldKind();
                } 
                else {UNREACHABLE("public input reader take_field can handle only fields");}
                if (value.at("field").is_double()) {
                    error =
                        "got double value for field argument. Probably the value is too big to be represented as "
                        "integer. You can put it in \"\" to avoid JSON parser restrictions.";
                }
                auto values = process_non_native_field(value.at("field"), arg_field_type);
                if (values.size() != arg_len) {
                    std::cerr << "values.size() != arg_len\n";
                    std::cerr << "values.size() = "  << values.size() << ", arg_len = " << arg_len<< std::endl;
                }
                return values;
            }


            bool take_field(llvm::Value *field_arg, llvm::Type *field_type, const boost::json::object &value) {
                std::vector<var> values = process_field(field_type, value);
                if (values.size() == 1) {
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
                if (elem_type->isIntegerTy()) {
                    return 1;
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
                    std::cerr << "json contains object with key \"array\", but value is not array \n";
                    return false;
                }
                const auto &json_arr = value.at("array").as_array();
                if (json_arr.size() != array_len) {
                    return false;
                }


                for (int i = 0; i < array_len; ++i) {
                    std::vector<var> elem_value;

                    if (elem_type->isCurveTy()){
                        if (json_arr[i].is_object()) {
                            elem_value = process_curve(elem_type, json_arr[i].as_object());
                            frame.memory.back().store_vector(elem_value, i);
                        } else {
                            UNREACHABLE("curve elemein in the array is not json object");
                        }
                    } 
                    else if(elem_type->isFieldTy()){
                        if (json_arr[i].is_object()) {
                            elem_value = process_field(elem_type, json_arr[i].as_object());
                            frame.memory.back().store_vector(elem_value, i);
                        } else {
                            UNREACHABLE("field in the array is not json object");
                        }
                    }
                    else {
                        elem_value = take_values(json_arr[i], elem_len);
                        if (elem_value.size() != elem_len) {
                            return false;
                        }
                        if (elem_len == 1) {
                            frame.memory.back().store_var(elem_value[0], i);
                        } 
                        else {
                            frame.memory.back().store_vector(elem_value, i);
                        }
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
