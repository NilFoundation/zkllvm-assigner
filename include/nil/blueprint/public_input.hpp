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

#include <nil/blueprint/layout_resolver.hpp>

#include <nil/blueprint/stack.hpp>

#include <iostream>
#include <boost/json/src.hpp>

namespace nil {
    namespace blueprint {

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
            PublicInputReader(stack_frame<var> &frame, program_memory<var> &memory, Assignment &assignmnt, LayoutResolver &layout_resolver) :
                frame(frame), layout_resolver(layout_resolver), memory(memory),
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

            std::vector<var> process_curve (llvm::EllipticCurveType *curve_type, const boost::json::object &value) {
                size_t arg_len = curve_arg_num<BlueprintFieldType>(curve_type);
                ASSERT_MSG(arg_len >= 2, "arg_len of curveTy cannot be less than two");
                if (value.size() != 1 || !value.contains("curve"))
                    UNREACHABLE("value.size() != 1 || !value.contains(\"curve\")");
                ASSERT_MSG(value.at("curve").is_array(), "curve element must be array!");
                ASSERT_MSG((value.at("curve").as_array().size() == 2), "curve element consists of two field elements!");

                llvm::GaloisFieldKind arg_field_type = curve_type->GetBaseFieldKind();
                std::vector<var> vector1 = process_non_native_field (value.at("curve").as_array()[0], arg_field_type);
                std::vector<var> vector2 = process_non_native_field (value.at("curve").as_array()[1], arg_field_type);
                vector1.insert(vector1.end(), vector2.begin(), vector2.end());
                return vector1;
            }

            bool take_curve(llvm::Value *curve_arg, llvm::Type *curve_type, const boost::json::object &value) {
                if (!llvm::isa<llvm::EllipticCurveType>(curve_type)) {
                    return false;
                }
                frame.vectors[curve_arg] = process_curve(llvm::cast<llvm::EllipticCurveType>(curve_type), value);
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

            std::vector<var> process_field (llvm::GaloisFieldType *field_type, const boost::json::object &value) {
                ASSERT(value.size() == 1 && value.contains("field"));
                size_t arg_len = field_arg_num<BlueprintFieldType>(field_type);
                ASSERT_MSG(arg_len != 0, "wrong input size");
                llvm::GaloisFieldKind arg_field_type = field_type->getFieldKind();

                if (value.at("field").is_double()) {
                    error =
                        "got double value for field argument. Probably the value is too big to be represented as "
                        "integer. You can put it in \"\" to avoid JSON parser restrictions.";
                }
                auto values = process_non_native_field(value.at("field"), arg_field_type);
                ASSERT(values.size() == arg_len);
                return values;
            }


            bool take_field(llvm::Value *field_arg, llvm::Type *field_type, const boost::json::object &value) {
                if (!field_type->isFieldTy()) {
                    return false;
                }
                std::vector<var> values = process_field(llvm::cast<llvm::GaloisFieldType>(field_type), value);
                if (values.size() == 1) {
                    frame.scalars[field_arg] = values[0];
                } else {
                    frame.vectors[field_arg] = values;
                }
                return true;
            }

            std::vector<var> process_int(const boost::json::object &value) {
                ASSERT(value.size() == 1 && value.contains("int"));
                std::vector<var> res;
                if (!parse_scalar(value.at("int"), assignmnt.public_input(0, public_input_idx))) {
                    return {};
                }
                res.push_back(var(0, public_input_idx++, false, var::column_type::public_input));
                return res;
            }

            bool take_int(llvm::Value *int_arg, const boost::json::object &value) {
                if (value.size() != 1 || !value.contains("int"))
                    return false;
                auto values = process_int(value);
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
                frame.vectors[vector_arg] = process_vector(llvm::cast<llvm::FixedVectorType>(vector_type), value);
                return frame.vectors[vector_arg].size() > 0;
            }

            bool try_string(llvm::Value *arg, llvm::Type *arg_type, const boost::json::object &value) {
                if (!arg_type->isPointerTy()) {
                    return false;
                }
                if (value.size() != 1 && !value.contains("string")) {
                    return false;
                }
                if (!value.at("string").is_string()) {
                    return false;
                }
                const auto &json_str = value.at("string").as_string();
                ptr_type ptr = memory.add_cells(std::vector<unsigned>(json_str.size() + 1, 1));
                assignmnt.public_input(0, public_input_idx) = ptr;
                auto pointer_var = var(0, public_input_idx++, false, var::column_type::public_input);
                frame.scalars[arg] = pointer_var;

                for (char c : json_str) {
                    assignmnt.public_input(0, public_input_idx) = c;
                    auto variable = var(0, public_input_idx++, false, var::column_type::public_input);
                    memory.store(ptr++, variable);
                }
                // Put '\0' at the end
                assignmnt.public_input(0, public_input_idx) = 0;
                auto final_zero = var(0, public_input_idx++, false, var::column_type::public_input);
                memory.store(ptr++, final_zero);

                return true;
            }

            bool try_struct(llvm::Value *arg, llvm::StructType *struct_type, const boost::json::object &value) {
                ptr_type ptr = memory.add_cells(layout_resolver.get_type_layout<BlueprintFieldType>(struct_type));
                process_struct(struct_type, value, ptr);
                assignmnt.public_input(0, public_input_idx) = ptr;
                auto variable = var(0, public_input_idx++, false, var::column_type::public_input);
                frame.scalars[arg] = variable;
                return true;
            }

            ptr_type process_array(llvm::ArrayType *array_type, const boost::json::object &value, ptr_type ptr) {
                ASSERT(value.size() == 1 && value.contains("array"));
                ASSERT(value.at("array").is_array());
                auto &arr = value.at("array").as_array();
                ASSERT(array_type->getNumElements() == arr.size());
                for (size_t i = 0; i < array_type->getNumElements(); ++i) {
                    ptr = dispatch_type(array_type->getElementType(), arr[i], ptr);
                }
                return ptr;
            }

            ptr_type process_struct(llvm::StructType *struct_type, const boost::json::object &value, ptr_type ptr) {
                ASSERT(value.size() == 1);
                if (value.contains("array") && struct_type->getNumElements() == 1 &&
                    struct_type->getElementType(0)->isArrayTy()) {
                    // Assuming std::array
                    return process_array(llvm::cast<llvm::ArrayType>(struct_type->getElementType(0)), value, ptr);
                }
                ASSERT(value.contains("struct") && value.at("struct").is_array());
                auto &arr = value.at("struct").as_array();
                ASSERT(arr.size() == struct_type->getNumElements());
                for (unsigned i = 0; i < struct_type->getNumElements(); ++i) {
                    auto elem_ty = struct_type->getElementType(i);
                    ptr = dispatch_type(elem_ty, arr[i], ptr);
                }
                return ptr;
            }

            std::vector<var> process_vector(llvm::FixedVectorType *vector_type, const boost::json::object &value) {
                ASSERT(value.size() == 1 && value.contains("vector"));
                ASSERT(value.at("vector").is_array());
                auto &vec = value.at("vector").as_array();
                ASSERT(vector_type->getNumElements() == vec.size());
                std::vector<var> res;
                for (size_t i = 0; i < vector_type->getNumElements(); ++i) {
                    auto elem_vector = process_leaf_type(vector_type->getElementType(), vec[i].as_object());
                    ASSERT(!elem_vector.empty());
                    res.insert(res.end(), elem_vector.begin(), elem_vector.end());
                }
                return res;
            }

            std::vector<var> process_leaf_type(llvm::Type *type, const boost::json::object &value) {
                switch (type->getTypeID()) {
                case llvm::Type::GaloisFieldTyID:
                    return process_field(llvm::cast<llvm::GaloisFieldType>(type), value);
                case llvm::Type::EllipticCurveTyID:
                    return process_curve(llvm::cast<llvm::EllipticCurveType>(type), value);
                case llvm::Type::IntegerTyID:
                    return process_int(value);
                case llvm::Type::FixedVectorTyID:
                    return process_vector(llvm::cast<llvm::FixedVectorType>(type), value);
                default:
                    UNREACHABLE("Unexpected leaf type");
                }
            }

            ptr_type dispatch_type(llvm::Type *type, const boost::json::value &value, ptr_type ptr) {
                switch (type->getTypeID()) {
                case llvm::Type::GaloisFieldTyID:
                case llvm::Type::EllipticCurveTyID:
                case llvm::Type::IntegerTyID:
                case llvm::Type::FixedVectorTyID:{
                    auto flat_components = process_leaf_type(type, value.as_object());
                    ASSERT(!flat_components.empty());
                    for (auto num : flat_components) {
                        memory.store(ptr++, num);
                    }
                    return ptr;
                }
                case llvm::Type::ArrayTyID:
                    return process_array(llvm::cast<llvm::ArrayType>(type), value.as_object(), ptr);
                case llvm::Type::StructTyID: {
                    return process_struct(llvm::cast<llvm::StructType>(type), value.as_object(), ptr);
                }
                default:
                    UNREACHABLE("Unsupported type");

                }
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
                        if (current_arg->hasStructRetAttr()) {
                            auto pointee = current_arg->getAttribute(llvm::Attribute::StructRet).getValueAsType();
                            ptr_type ptr = memory.add_cells(layout_resolver.get_type_layout<BlueprintFieldType>(pointee));
                            assignmnt.public_input(0, public_input_idx) = ptr;
                            frame.scalars[current_arg] = var(0, public_input_idx++, false, var::column_type::public_input);
                            ret_gap += 1;
                            continue;
                        }
                        if (current_arg->hasAttribute(llvm::Attribute::ByVal)) {
                            auto pointee = current_arg->getAttribute(llvm::Attribute::ByVal).getValueAsType();
                            ASSERT(pointee->isStructTy());
                            if (try_struct(current_arg, llvm::cast<llvm::StructType>(pointee), current_value))
                                continue;
                        }
                        if (!try_string(current_arg, arg_type, current_value)) {
                            std::cerr << "Unhandled pointer argument" << std::endl;
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
            program_memory<var> &memory;
            Assignment &assignmnt;
            LayoutResolver &layout_resolver;
            size_t public_input_idx;
            std::string error;
        };
    }    // namespace blueprint
}    // namespace nil


#endif  // CRYPTO3_ASSIGNER_PUBLIC_INPUT_HPP
