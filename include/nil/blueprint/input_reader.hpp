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
#include <nil/blueprint/signature_parser.hpp>
#include <nil/blueprint/stack.hpp>
#include <nil/blueprint/non_native_marshalling.hpp>

#include <iostream>
#include <fstream>
#include <boost/json/src.hpp>

#include <nil/blueprint/logger.hpp>

namespace nil {
    namespace blueprint {

        template<typename BlueprintFieldType, typename var, typename Assignment>
        class InputReader {
        public:
            InputReader(stack_frame<var> &frame, program_memory<var> &memory, Assignment &assignmnt,
                        LayoutResolver &layout_resolver, bool has_values) :
                frame(frame),
                layout_resolver(layout_resolver), memory(memory), assignmnt(assignmnt), has_values(has_values) {
                ASSERT(public_input_only == false);
                reset();
            }

            InputReader(stack_frame<var> &frame, program_memory<var> &memory, Assignment &assignmnt,
                        LayoutResolver &layout_resolver) :
                frame(frame),
                layout_resolver(layout_resolver), memory(memory), assignmnt(assignmnt), has_values(true) {
                ASSERT(public_input_only == true);
                reset();
            }

            void reset() {
                parsed_public_input.clear();
                public_input_idx = 0;
                private_input_idx = 0;
                constant_idx = 0;
                error.str("");
                pub_iter = 0;
                priv_iter = 0;
            }

            constexpr static bool public_input_only = std::is_same_v<Assignment, std::nullptr_t>;

            template<typename InputType>
            var put_into_assignment(InputType &input, bool is_private) {
                if constexpr (public_input_only) {
                    ASSERT(!is_private);
                    parsed_public_input.push_back(input);
                    return var();
                } else {
                    if (is_private) {
                        assignmnt.private_storage(private_input_idx) = input;
                        return var(Assignment::private_storage_index, private_input_idx++, false, var::column_type::public_input);
                    } else {
                        assignmnt.public_input(0, public_input_idx) = input;
                        return var(0, public_input_idx++, false, var::column_type::public_input);
                    }
                }
            }

            template<typename InputType>
            var pointer_into_assignment(InputType &ptr) {
                if constexpr (public_input_only) {
                    return var();
                } else {
                    assignmnt.constant(1, constant_idx) = ptr; // TODO: column index is hardcoded but shouldn't be in the future
                    return var(1, constant_idx++, false, var::column_type::constant);
                }
            }

            bool check_curve(const signature_node &node, llvm::EllipticCurveKind curve_kind) {
                if (node.elem != json_elem::CURVE) {
                    error << "Expected curve argument in the input, got \"" << node.elem << "\"";
                    return false;
                }
                if (node.children.size() == 1) {
                    auto corresponding_elem = [](llvm::EllipticCurveKind curve_kind) {
                        switch (curve_kind) {
                            case llvm::ELLIPTIC_CURVE_PALLAS:
                                return json_elem::PALLAS;
                            case llvm::ELLIPTIC_CURVE_CURVE25519:
                                return json_elem::ED25519;
                            case llvm::ELLIPTIC_CURVE_BLS12381:
                                return json_elem::BLS12381;
                            default:
                                UNREACHABLE("Error in parsing of signature");
                        }
                    };
                    json_elem child_elem = node.children[0].elem;
                    json_elem expected_elem = corresponding_elem(curve_kind);
                    if (child_elem != expected_elem) {
                        error << "Wrong kind of curve \"" << child_elem << "\", expected \"" << expected_elem << "\"";
                        return false;
                    }
                }
                return true;
            }

            std::vector<var> process_curve(llvm::EllipticCurveType *curve_type, const boost::json::value &curve_value,
                                           const signature_node &node, bool is_private) {
                size_t arg_len = curve_arg_num<BlueprintFieldType>(curve_type);
                ASSERT_MSG(arg_len >= 2, "arg_len of curveTy cannot be less than two");
                std::vector<var> vector1;
                std::vector<var> vector2;
                llvm::GaloisFieldKind arg_field_type = curve_type->GetBaseFieldKind();
                if (!has_values) {
                    vector1 = process_empty_field(arg_field_type, is_private);
                    vector2 = process_empty_field(arg_field_type, is_private);
                } else {
                    if (!check_curve(node, curve_type->getCurveKind())) {
                        return {};
                    }
                    if (!(curve_value.is_array() && curve_value.as_array().size() == 2)) {
                        error << "curve argument must be array and must consist of two field elements, got \""
                            << curve_value << "\"";
                        return {};
                    }

                    vector1 = process_non_native_field (curve_value.as_array()[0], arg_field_type, is_private);
                    vector2 = process_non_native_field(curve_value.as_array()[1], arg_field_type, is_private);
                    if (vector1.empty() || vector2.empty()) {
                        return {};
                    }
                }
                vector1.insert(vector1.end(), vector2.begin(), vector2.end());
                return vector1;
            }

            bool take_curve(llvm::Value *curve_arg, llvm::Type *curve_type, const boost::json::value &value,
                            const signature_node &node, bool is_private) {
                ASSERT(llvm::isa<llvm::EllipticCurveType>(curve_type));
                frame.vectors[curve_arg] = process_curve(llvm::cast<llvm::EllipticCurveType>(curve_type), value, node, is_private);
                return !frame.vectors[curve_arg].empty();
            }

            std::vector<var> put_field_into_assignmnt (std::vector<typename BlueprintFieldType::value_type> input, bool is_private) {

                std::vector<var> res;

                for (std::size_t i = 0; i < input.size(); i++) {
                    res.push_back(put_into_assignment(input[i], is_private));
                }

                return res;
            }

            std::vector<var> process_empty_field (llvm::GaloisFieldKind arg_field_type, bool is_private) {
                std::vector<var> res;
                size_t arg_len = field_kind_size<BlueprintFieldType>(arg_field_type);
                typename BlueprintFieldType::value_type zero_val = 0;
                for (std::size_t i = 0; i < arg_len; i++) {
                    res.push_back(put_into_assignment(zero_val, is_private));
                }
                return res;
            }

            std::vector<var> process_non_native_field (const boost::json::value &value, llvm::GaloisFieldKind arg_field_type, bool is_private) {
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
                    res = put_field_into_assignmnt(chunked_non_native_field_element, is_private);
                    return res;
                    break;

                case boost::json::kind::uint64:
                    non_native_number = typename BlueprintFieldType::extended_integral_type(value.as_uint64());
                    chunked_non_native_field_element = extended_integral_into_vector<BlueprintFieldType> (arg_field_type, non_native_number);
                    res = put_field_into_assignmnt(chunked_non_native_field_element, is_private);
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

                    res = put_field_into_assignmnt(chunked_non_native_field_element, is_private);
                    return res;
                    break;
                default:
                    error << "Expected int or string as a field value, got \"" << value << "\"";
                    return {};
                }
            }

            bool check_field(const signature_node &node, llvm::GaloisFieldKind kind) {
                if (node.elem != json_elem::FIELD) {
                    error << "Expected field argument in the input, got \"" << node.elem << "\"";
                    return false;
                }
                if (node.children.size() == 1) {
                    auto corresponding_elem = [](llvm::GaloisFieldKind kind) {
                        switch (kind) {
                            case llvm::GALOIS_FIELD_PALLAS_BASE:
                                return json_elem::PALLAS_BASE;
                            case llvm::GALOIS_FIELD_CURVE25519_BASE:
                                return json_elem::ED25519_BASE;
                            case llvm::GALOIS_FIELD_BLS12381_BASE:
                                return json_elem::BLS12381_BASE;
                            default:
                                UNREACHABLE("Error in parsing");
                        }
                    };
                    json_elem child_elem = node.children[0].elem;
                    json_elem expected_elem = corresponding_elem(kind);
                    if (child_elem != expected_elem) {
                        error << "Wrong kind of field \"" << child_elem << "\", expected \"" << expected_elem << "\"";
                        return false;
                    }
                }
                return true;
            }

            std::vector<var> process_field(llvm::GaloisFieldType *field_type, const boost::json::value &value,
                                           const signature_node &node, bool is_private) {
                llvm::GaloisFieldKind arg_field_type = field_type->getFieldKind();
                if (!has_values) {
                    return process_empty_field(arg_field_type, is_private);
                }
                if (!check_field(node, arg_field_type)) {
                    return {};
                }
                size_t arg_len = field_arg_num<BlueprintFieldType>(field_type);
                ASSERT_MSG(arg_len != 0, "wrong input size");

                if (value.is_double()) {
                    std::cerr << "error in json value:\n" << value << "\n";
                    error <<
                        "got double value for field argument. Probably the value is too big to be represented as "
                        "integer. You can put it in \"\" to avoid JSON parser restrictions.";
                    return {};
                }
                return process_non_native_field(value, arg_field_type, is_private);
            }


            bool take_field(llvm::Value *field_arg, llvm::Type *field_type, const boost::json::value &value,
                            const signature_node &node, bool is_private) {
                ASSERT(field_type->isFieldTy());
                std::vector<var> values = process_field(llvm::cast<llvm::GaloisFieldType>(field_type), value, node, is_private);
                if (values.empty()) {
                    return false;
                }
                if (values.size() == 1) {
                    frame.scalars[field_arg] = values[0];
                } else {
                    frame.vectors[field_arg] = values;
                }
                return true;
            }

            std::vector<var> process_int(const boost::json::value &value, const signature_node &node, std::size_t bitness,
                                         bool is_private) {
                std::vector<var> res = std::vector<var>(1);
                if (!has_values) {
                    typename BlueprintFieldType::value_type zero_val = 0;
                    res[0] = put_into_assignment(zero_val, is_private);
                    return res;
                }

                if (node.elem != json_elem::INT) {
                    error << "Expected int argument in the input, got \"" << node.elem << "\"";
                    return {};
                }

                typename BlueprintFieldType::value_type out;

                switch (value.kind()) {
                case boost::json::kind::int64:
                    if (bitness < 64 && value.as_int64() >> bitness > 0) {
                        error << "int value " << value.as_int64() << " does not fit into " << bitness << " bits";
                        return {};
                    }
                    out = value.as_int64();
                    break;
                case boost::json::kind::uint64:
                    if (bitness < 64 && value.as_uint64() >> bitness > 0) {
                        error << "uint value " << value.as_uint64() << " does not fit into " << bitness << " bits";
                        return {};
                    }
                    out = value.as_uint64();
                    break;
                case boost::json::kind::double_: {
                    error <<
                        "got double value for int argument. Probably the value is too big to be represented as "
                        "integer. You can put it in \"\" to avoid JSON parser restrictions.";
                    return {};
                }
                case boost::json::kind::string: {
                    const std::size_t buflen = 256;
                    char buf[buflen];

                    std::size_t numlen = value.as_string().size();

                    if (numlen > buflen - 1) {
                        error << "value " << value.as_string() << " exceeds buffer size (" << buflen - 1 << ")";
                        return {};
                    }

                    value.as_string().copy(buf, numlen);
                    buf[numlen] = '\0';
                    typename BlueprintFieldType::extended_integral_type number = typename BlueprintFieldType::extended_integral_type(buf);
                    typename BlueprintFieldType::extended_integral_type one = 1;
                    if (bitness <= 128) {
                        error << "integers larger than 128 bits are not supported, try to use field types";
                        return {};
                    }
                    typename BlueprintFieldType::extended_integral_type max_size = one << bitness;
                    if (number >= max_size) {
                        error << "value " << buf << " does not fit into " << bitness << " bits, try to use other type";
                        return {};
                    }
                    out = number;
                    break;
                }
                default:
                    error << "Expected int or string as an int argument, got \"" << value << "\"";
                    return {};
                }

                res[0] = put_into_assignment(out, is_private);
                return res;
            }

            bool take_int(llvm::Value *int_arg, const boost::json::value &value, const signature_node &node,
                          bool is_private) {
                std::size_t bitness = int_arg->getType()->getPrimitiveSizeInBits();
                auto values = process_int(value, node, bitness, is_private);
                if (values.size() != 1)
                    return false;
                frame.scalars[int_arg] = values[0];
                return true;
            }

            bool take_vector(llvm::Value *vector_arg, llvm::Type *vector_type, const boost::json::value &value,
                             const signature_node &node, bool is_private) {
                size_t arg_len = llvm::cast<llvm::FixedVectorType>(vector_type)->getNumElements();
                frame.vectors[vector_arg] =
                    process_vector(llvm::cast<llvm::FixedVectorType>(vector_type), value, node, is_private);
                return frame.vectors[vector_arg].size() > 0;
            }

            bool try_string(llvm::Value *arg, llvm::Type *arg_type, const boost::json::value &value,
                            const signature_node &node, bool is_private) {
                if (!arg_type->isPointerTy()) {
                    return false;
                }

                if (!has_values) {
                    type_layout string_layout(1, {1,0});
                    ptr_type ptr = memory.add_cells(string_layout);
                    auto pointer_var = pointer_into_assignment(ptr);
                    frame.scalars[arg] = pointer_var;
                    return true;
                }

                if (node.elem != json_elem::STRING) {
                    error << "Expected string argument in the input, got \"" << node.elem << "\"";
                    return false;
                }
                if (!value.is_string()) {
                    return false;
                }
                const auto &json_str = value.as_string();
                size_t string_size = json_str.size() + 1;  // add memory for '\0'
                type_layout string_layout(string_size, {1,0});
                ptr_type ptr = memory.add_cells(string_layout);
                auto pointer_var = pointer_into_assignment(ptr);
                frame.scalars[arg] = pointer_var;

                for (char c : json_str) {
                    auto variable = put_into_assignment(c, is_private);
                    memory.store(ptr++, variable);
                }
                // Put '\0' at the end
                typename BlueprintFieldType::value_type zero_val = 0;
                auto final_zero = put_into_assignment(zero_val, is_private);
                memory.store(ptr++, final_zero);

                return true;
            }

            bool try_struct(llvm::Value *arg, llvm::StructType *struct_type, const boost::json::value &value,
                            const signature_node &node, bool is_private) {
                ptr_type ptr = memory.add_cells(layout_resolver.get_type_layout<BlueprintFieldType>(struct_type));
                if (process_struct(struct_type, value, node, ptr, is_private) == ptr_type(0)) {
                    return false;
                }
                auto variable = pointer_into_assignment(ptr);
                frame.scalars[arg] = variable;
                return true;
            }

            bool try_array(llvm::Value *arg, llvm::ArrayType *array_type, const boost::json::value &value,
                           const signature_node &node, bool is_private) {
                ptr_type ptr = memory.add_cells(layout_resolver.get_type_layout<BlueprintFieldType>(array_type));
                if (process_array(array_type, value, node, ptr, is_private) == ptr_type(0)) {
                    return false;
                }
                auto variable = pointer_into_assignment(ptr);
                frame.scalars[arg] = variable;
                return true;
            }

            ptr_type process_array(llvm::ArrayType *array_type, const boost::json::value &value, const signature_node &node, ptr_type ptr, bool is_private) {
                if (!has_values) {
                    for (size_t i = 0; i < array_type->getNumElements(); ++i) {
                        ptr = dispatch_type(array_type->getElementType(), value, node, ptr, is_private);
                    }
                    return ptr;
                }

                if (node.elem != json_elem::ARRAY) {
                    error << "Expected array argument in the input, got \"" << node.elem << "\"";
                    return false;
                }

                if (!value.is_array()) {
                    error << "Array argument must be represented as JSON array, got \"" << value << "\"";
                    return ptr_type(0);
                }
                auto &arr = value.as_array();
                if (array_type->getNumElements() != arr.size()) {
                    error << "Expected an array with " << array_type->getNumElements() << " arguments, got \"" << arr
                          << "\"";
                    return ptr_type(0);
                }
                for (size_t i = 0; i < array_type->getNumElements(); ++i) {
                    if (node.children.size() == 1) {
                        ptr = dispatch_type(array_type->getElementType(), arr[i], node.children[0], ptr, is_private);
                    } else {
                        if (!arr[i].is_object() || arr[i].as_object().size() != 1) {
                            error << "Expected object with a signature as an array elem, got \"" << arr[i] << "\"";
                            return ptr_type(0);
                        }
                        std::string signature(arr[i].as_object().begin()->key());
                        signature_parser sp;
                        if (!sp.parse(signature)) {
                            error << sp.get_error();
                            return ptr_type(0);
                        }
                        ptr = dispatch_type(array_type->getElementType(), arr[i].as_object().at(signature), sp.get_tree(),
                                            ptr, is_private);
                    }

                    if (ptr == ptr_type(0)) {
                        return ptr_type(0);
                    }
                }

                return ptr;
            }

            bool check_struct(const signature_node &node, llvm::StructType *struct_type) {
                if (node.elem != json_elem::STRUCT) {
                    error << "Expected struct argument in the input, got \"" << node.elem << "\"";
                    return false;
                }
                size_t children_size = node.children.size();
                if (children_size != 0 && children_size != struct_type->getNumElements()) {
                    error << "Wrong number of elements in struct signature, " << children_size << "instead of "
                          << struct_type->getNumElements();
                    return false;
                }
                return true;
            }

            ptr_type process_struct(llvm::StructType *struct_type, const boost::json::value &value, const signature_node &node,
                                    ptr_type ptr, bool is_private) {
                if (!has_values) {
                    for (unsigned i = 0; i < struct_type->getNumElements(); ++i) {
                        auto elem_ty = struct_type->getElementType(i);
                        ptr = dispatch_type(elem_ty, value, node, ptr, is_private);
                    }
                    return ptr;
                }
                if (node.elem == json_elem::ARRAY && struct_type->getNumElements() == 1 &&
                    struct_type->getElementType(0)->isArrayTy()) {
                    // Assuming std::array
                    return process_array(llvm::cast<llvm::ArrayType>(struct_type->getElementType(0)), value, node, ptr,
                                         is_private);
                }

                if (!check_struct(node, struct_type)) {
                    return ptr_type(0);
                }
                if (!value.is_array()) {
                    error << "Struct argument must be represented as JSON array, got \"" << value << "\"";
                    return ptr_type(0);
                }
                auto &arr = value.as_array();
                if (arr.size() != struct_type->getNumElements()) {
                    error << "Expected a struct with " << struct_type->getNumElements() << " elements, got \"" << arr
                          << "\"";
                    return ptr_type(0);
                }
                for (unsigned i = 0; i < struct_type->getNumElements(); ++i) {
                    auto elem_ty = struct_type->getElementType(i);
                    if (node.children.size() == struct_type->getNumElements()) {
                        ptr = dispatch_type(elem_ty, arr[i], node.children[i], ptr, is_private);
                    } else {
                        if (!arr[i].is_object() || arr[i].as_object().size() != 1) {
                            error << "Expected object with a signature as a struct elem, got \"" << arr[i] << "\"";
                            return ptr_type(0);
                        }
                        std::string signature(arr[i].as_object().begin()->key());
                        signature_parser sp;
                        if (!sp.parse(signature)) {
                            error << sp.get_error();
                            return ptr_type(0);
                        }
                        ptr = dispatch_type(elem_ty, arr[i].as_object().at(signature), sp.get_tree(), ptr, is_private);
                    }
                    if (ptr == ptr_type(0)) {
                        return ptr_type(0);
                    }
                }
                return ptr;
            }

            std::vector<var> process_vector(llvm::FixedVectorType *vector_type, const boost::json::value &value,
                                            const signature_node &node, bool is_private) {
                if (!has_values) {
                    std::vector<var> res;
                    for (size_t i = 0; i < vector_type->getNumElements(); ++i) {
                        auto elem_vector = process_leaf_type(vector_type->getElementType(), value, node, is_private);
                        ASSERT(!elem_vector.empty());
                        res.insert(res.end(), elem_vector.begin(), elem_vector.end());
                    }
                    return res;
                }

                if (node.elem != json_elem::VECTOR) {
                    error << "Expected vector argument in the input, got \"" << node.elem << "\"";
                    return {};
                }

                if (!value.is_array()) {
                    error << "Vector argument must be represented as JSON array, got \"" << value.at("vector") << "\"";
                    return {};
                }
                auto &vec = value.as_array();
                if (vector_type->getNumElements() != vec.size()) {
                    error << "Expected a vector with " << vector_type->getNumElements() << " elements, got \"" << vec
                          << "\"";
                    return {};
                }
                std::vector<var> res;
                for (size_t i = 0; i < vector_type->getNumElements(); ++i) {
                    std::vector<var> elem_vector;
                    if (node.children.size() == 1) {
                        elem_vector = process_leaf_type(vector_type->getElementType(), vec[i], node.children[0], is_private);
                    } else {
                        if (!vec[i].is_object() || vec[i].as_object().size() != 1) {
                            error << "Expected object with signature as a vector elem, got \"" << vec[i] << "\"";
                            return {};
                        }
                        std::string signature(vec[i].as_object().begin()->key());
                        signature_parser sp;
                        if (!sp.parse(signature)) {
                            error << sp.get_error();
                            return {};
                        }
                        elem_vector = process_leaf_type(vector_type->getElementType(), vec[i].as_object().at(signature),
                                                        sp.get_tree(), is_private);
                    }
                    if (elem_vector.empty()) {
                        return {};
                    }
                    res.insert(res.end(), elem_vector.begin(), elem_vector.end());
                }
                return res;
            }

            std::vector<var> process_leaf_type(llvm::Type *type, const boost::json::value &value, const signature_node &node, bool is_private) {
                switch (type->getTypeID()) {
                case llvm::Type::GaloisFieldTyID:
                    return process_field(llvm::cast<llvm::GaloisFieldType>(type), value, node, is_private);
                case llvm::Type::EllipticCurveTyID:
                    return process_curve(llvm::cast<llvm::EllipticCurveType>(type), value, node, is_private);
                case llvm::Type::IntegerTyID:
                    return process_int(value, node, type->getPrimitiveSizeInBits(), is_private);
                case llvm::Type::FixedVectorTyID:
                    return process_vector(llvm::cast<llvm::FixedVectorType>(type), value, node, is_private);
                default:
                    UNREACHABLE("Unexpected leaf type");
                }
            }

            ptr_type dispatch_type(llvm::Type *type, const boost::json::value &value, const signature_node &node, ptr_type ptr,
                                   bool is_private) {
                switch (type->getTypeID()) {
                case llvm::Type::GaloisFieldTyID:
                case llvm::Type::EllipticCurveTyID:
                case llvm::Type::IntegerTyID:
                case llvm::Type::FixedVectorTyID:{
                    auto flat_components = process_leaf_type(type, value, node, is_private);
                    if (flat_components.empty()) {
                        return ptr_type(0);
                    }
                    for (auto num : flat_components) {
                        memory.store(ptr++, num);
                    }
                    return ptr;
                }
                case llvm::Type::ArrayTyID:
                    return process_array(llvm::cast<llvm::ArrayType>(type), value, node, ptr, is_private);
                case llvm::Type::StructTyID: {
                    return process_struct(llvm::cast<llvm::StructType>(type), value, node, ptr, is_private);
                }
                default:
                    UNREACHABLE("Unsupported type");

                }
            }

            void increment_iter (bool is_private) {
                is_private ? priv_iter++ : pub_iter++;
            }

            void dump_public_input(const std::string &output_file) {
                ASSERT(public_input_only);
                std::ofstream f(output_file);
                for (auto item : parsed_public_input) {
                    f << item.data << " ";
                    f << std::endl;
                }
            }

            bool fill_public_input(
                const llvm::Function &function,
                const boost::json::array &public_input,
                const boost::json::array &private_input,
                logger &log
            ) {
                size_t ret_gap = 0;

                for (size_t i = 0; i < function.arg_size(); ++i) {
                    llvm::Argument *current_arg = function.getArg(i);

                    llvm::Type *arg_type = current_arg->getType();
                    if (current_arg->hasStructRetAttr()) {
                        ret_gap = 1;
                        if (public_input_only) {
                            continue;
                        }
                        ASSERT(llvm::isa<llvm::PointerType>(arg_type));
                        auto pointee = current_arg->getAttribute(llvm::Attribute::StructRet).getValueAsType();
                        ptr_type ptr = memory.add_cells(layout_resolver.get_type_layout<BlueprintFieldType>(pointee));
                        frame.scalars[current_arg] = pointer_into_assignment(ptr);
                        continue;
                    }

                    bool is_private = current_arg->hasAttribute(llvm::Attribute::PrivateInput);

                    if (has_values) {
                        if (is_private) {
                            if (public_input_only) {
                                increment_iter(is_private);
                                continue;
                            }
                            if (private_input.size() <= priv_iter || !private_input[priv_iter].is_object()) {
                                if (private_input.size() == 0) {
                                    error << "got argument with [[private_input]] attribute, but private input file was not provided or is empty (use -p flag to provide file name).";
                                    return false;
                                }
                                error << "not enough values in the private input file.";
                                return false;
                            }
                        }
                        else {
                            if (public_input.size() <= pub_iter || !public_input[pub_iter].is_object()) {
                                if (public_input.size() == 0) {
                                    error << "got argument without [[private_input]], but public input file was not provided or is empty (use -i flag to provide file name).";
                                    return false;
                                }
                                error << "not enough values in the public input file.";
                                return false;
                            }
                        }
                    }

                    boost::json::value empty_value;
                    boost::json::object empty_object;
                    const boost::json::value &input_elem =
                        has_values ?
                            (is_private ? private_input[priv_iter].as_object() : public_input[pub_iter].as_object()) :
                            empty_value;

                    if (has_values && !input_elem.is_object()) {
                        error << "Expected JSON object as a part of an input array, got \"" << input_elem << "\"";
                        return false;
                    }
                    const boost::json::object &arg_obj = has_values ? input_elem.as_object() : empty_object;
                    std::string signature;
                    signature_parser sp;
                    if (has_values) {
                        if (arg_obj.size() != 1) {
                            error << "Input object size must be 1, got \"" << arg_obj << "\"";
                            return false;
                        }
                        signature = std::string(arg_obj.begin()->key());
                        if (!sp.parse(signature)) {
                            error << sp.get_error();
                            return false;
                        }
                    }
                    const boost::json::value &current_value = has_values ? arg_obj.at(signature) : empty_value;
                    increment_iter(is_private);

                    if (llvm::isa<llvm::PointerType>(arg_type)) {
                        if (current_arg->hasAttribute(llvm::Attribute::ByVal)) {
                            auto pointee = current_arg->getAttribute(llvm::Attribute::ByVal).getValueAsType();
                            if (pointee->isStructTy()) {
                                if (!try_struct(current_arg, llvm::cast<llvm::StructType>(pointee), current_value,
                                                sp.get_tree(), is_private)) {
                                    return false;
                                }
                                continue;
                            }
                            if (pointee->isArrayTy()) {
                                if (!try_array(current_arg, llvm::cast<llvm::ArrayType>(pointee), current_value,
                                               sp.get_tree(), is_private)) {
                                    return false;
                                }
                                continue;
                            }
                            UNREACHABLE("Unsupported pointer type");
                        }
                        if (!try_string(current_arg, arg_type, current_value, sp.get_tree(), is_private)) {
                            error << "Unhandled pointer argument";
                            return false;
                        }
                    } else if (llvm::isa<llvm::FixedVectorType>(arg_type)) {
                        if (!take_vector(current_arg, arg_type, current_value, sp.get_tree(), is_private))
                            return false;
                    } else if (llvm::isa<llvm::EllipticCurveType>(arg_type)) {
                        if (!take_curve(current_arg, arg_type, current_value, sp.get_tree(), is_private))
                            return false;
                    } else if (llvm::isa<llvm::GaloisFieldType>(arg_type)) {
                        if (!take_field(current_arg, arg_type, current_value, sp.get_tree(), is_private))
                            return false;
                    } else if (llvm::isa<llvm::IntegerType>(arg_type)) {
                        if (!take_int(current_arg, current_value, sp.get_tree(), is_private))
                            return false;
                    }
                    else {
                        UNREACHABLE("unsupported input type");
                    }
                }

                // Check if there are remaining elements of input
                if (has_values && (function.arg_size() - ret_gap!= public_input.size() + private_input.size())) {
                    log.debug(boost::format("public_input size: %1%") % public_input.size());
                    log.debug(boost::format("private_input size: %1%") % private_input.size());
                    log.debug(boost::format("ret_gap: %1%") % ret_gap);
                    log.debug(boost::format("function.arg_size(): %1%") % function.arg_size());

                    error << "too many values in the input files, public + private input sizes must be equal to function.arg_size - ret_gap";
                    return false;
                }

                return true;
            }
            size_t get_idx() const {
                return constant_idx;
            }

            std::string get_error() const {
                return error.str();
            }

        private:
            stack_frame<var> &frame;
            program_memory<var> &memory;
            Assignment &assignmnt;
            LayoutResolver &layout_resolver;
            std::vector<typename BlueprintFieldType::value_type> parsed_public_input;
            size_t public_input_idx;
            size_t private_input_idx;
            size_t constant_idx;
            std::ostringstream error;
            size_t pub_iter;
            size_t priv_iter;
            bool has_values;
        };
    }   // namespace blueprint
}    // namespace nil


#endif  // CRYPTO3_ASSIGNER_PUBLIC_INPUT_HPP
