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
#include <nil/blueprint/non_native_marshalling.hpp>

#include <iostream>
#include <boost/json/src.hpp>

namespace nil {
    namespace blueprint {
        template<typename BlueprintFieldType, typename var, typename Assignment>
        class InputReader {
        public:
            InputReader(stack_frame<var> &frame, program_memory<var> &memory, Assignment &assignmnt, LayoutResolver &layout_resolver) :
                frame(frame), layout_resolver(layout_resolver), memory(memory),
                assignmnt(assignmnt), public_input_idx(0), private_input_idx(0) {}

            template<typename InputType>
            var put_into_assignment(InputType &input, bool is_private) {
                if (is_private) {
                    assignmnt.private_storage(private_input_idx) = input;
                    return var(Assignment::PRIVATE_STORAGE_INDEX, private_input_idx++, false, var::column_type::public_input);
                } else {
                    assignmnt.public_input(0, public_input_idx) = input;
                    return var(0, public_input_idx++, false, var::column_type::public_input);
                }
            }

            std::vector<var> process_curve (llvm::EllipticCurveType *curve_type, const boost::json::object &value, bool is_private) {
                size_t arg_len = curve_arg_num<BlueprintFieldType>(curve_type);
                ASSERT_MSG(arg_len >= 2, "arg_len of curveTy cannot be less than two");
                if (value.size() != 1 || !value.contains("curve")) {
                    std::cerr << "error in json value:\n" << value << "\n";
                    UNREACHABLE("value.size() != 1 || !value.contains(\"curve\")");
                }
                ASSERT_MSG(value.at("curve").is_array(), "curve element must be array!");
                ASSERT_MSG((value.at("curve").as_array().size() == 2), "curve element consists of two field elements!");

                llvm::GaloisFieldKind arg_field_type = curve_type->GetBaseFieldKind();
                std::vector<var> vector1 = process_non_native_field (value.at("curve").as_array()[0], arg_field_type, is_private);
                std::vector<var> vector2 = process_non_native_field (value.at("curve").as_array()[1], arg_field_type, is_private);
                vector1.insert(vector1.end(), vector2.begin(), vector2.end());
                return vector1;
            }

            bool take_curve(llvm::Value *curve_arg, llvm::Type *curve_type, const boost::json::object &value, bool is_private) {
                if (!llvm::isa<llvm::EllipticCurveType>(curve_type)) {
                    return false;
                }
                frame.vectors[curve_arg] = process_curve(llvm::cast<llvm::EllipticCurveType>(curve_type), value, is_private);
                return true;
            }

            std::vector<var> put_field_into_assignmnt (std::vector<typename BlueprintFieldType::value_type> input, bool is_private) {

                std::vector<var> res;

                for (std::size_t i = 0; i < input.size(); i++) {
                    res.push_back(put_into_assignment(input[i], is_private));
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
                    return {};
                }
            }

            std::vector<var> process_field (llvm::GaloisFieldType *field_type, const boost::json::object &value, bool is_private) {
                ASSERT(llvm::isa<llvm::GaloisFieldType>(field_type));
                if (value.size() != 1 || !value.contains("field")){
                    std::cerr << "error in json value:\n" << value << "\n";
                    UNREACHABLE("value.size() != 1 || !value.contains(\"field\")");
                }
                size_t arg_len = field_arg_num<BlueprintFieldType>(field_type);
                ASSERT_MSG(arg_len != 0, "wrong input size");
                llvm::GaloisFieldKind arg_field_type = field_type->getFieldKind();

                if (value.at("field").is_double()) {
                    std::cerr << "error in json value:\n" << value << "\n";
                    error =
                        "got double value for field argument. Probably the value is too big to be represented as "
                        "integer. You can put it in \"\" to avoid JSON parser restrictions.";
                    UNREACHABLE("got double type value");
                }
                auto values = process_non_native_field(value.at("field"), arg_field_type, is_private);
                if (values.size() != arg_len) {
                    std::cerr << "error in json value:\n" << value << "\n";
                    std::cerr << "values.size() != arg_len\n";
                    std::cerr << "values.size() = "  << values.size() << ", arg_len = " << arg_len<< std::endl;
                    UNREACHABLE("value size != arg_len");
                }
                return values;
            }


            bool take_field(llvm::Value *field_arg, llvm::Type *field_type, const boost::json::object &value, bool is_private) {
                if (!field_type->isFieldTy()) {
                    return false;
                }
                std::vector<var> values = process_field(llvm::cast<llvm::GaloisFieldType>(field_type), value, is_private);
                if (values.size() == 1) {
                    frame.scalars[field_arg] = values[0];
                } else {
                    frame.vectors[field_arg] = values;
                }
                return true;
            }

            std::vector<var> process_int(const boost::json::object &object, std::size_t bitness, bool is_private) {
                ASSERT(object.size() == 1 && object.contains("int"));
                std::vector<var> res = std::vector<var>(1);

                typename BlueprintFieldType::value_type out;

                switch (object.at("int").kind()) {
                case boost::json::kind::int64:
                    if (bitness < 64 && object.at("int").as_int64() >> bitness > 0) {
                        std::cerr << "value " << object.at("int").as_int64() << " does not fit into " << bitness << " bits\n";
                        UNREACHABLE("one of the input values is too large");
                    }
                    out = object.at("int").as_int64();
                    break;
                case boost::json::kind::uint64:
                    if (bitness < 64 && object.at("int").as_uint64() >> bitness > 0) {
                        std::cerr << "value " << object.at("int").as_uint64() << " does not fit into " << bitness << " bits\n";
                        UNREACHABLE("one of the input values is too large");
                    }
                    out = object.at("int").as_uint64();
                    break;
                case boost::json::kind::double_: {
                    std::cerr << "error in json value " <<  boost::json::serialize(object) << "\n";
                    error =
                        "got double value for int argument. Probably the value is too big to be represented as "
                        "integer. You can put it in \"\" to avoid JSON parser restrictions.";
                    UNREACHABLE(error);
                }
                case boost::json::kind::string: {
                    const std::size_t buflen = 256;
                    char buf[buflen];

                    std::size_t numlen = object.at("int").as_string().size();

                    if (numlen > buflen - 1) {
                        std::cerr << "value " << object.at("int").as_string() << " exceeds buffer size (" << buflen - 1 << ")\n";
                        UNREACHABLE("value size exceeds buffer size");
                    }

                    object.at("int").as_string().copy(buf, numlen);
                    buf[numlen] = '\0';
                    typename BlueprintFieldType::extended_integral_type number = typename BlueprintFieldType::extended_integral_type(buf);
                    typename BlueprintFieldType::extended_integral_type one = 1;
                    ASSERT_MSG(bitness <= 128, "integers larger than 128 bits are not supported, try to use field types");
                    typename BlueprintFieldType::extended_integral_type max_size = one << bitness;
                    if (number >= max_size) {
                        std::cout << "value " << buf << " does not fit into " << bitness << " bits, try to use other type\n";
                        UNREACHABLE("input value is too big");
                    }
                    out = number;
                    break;
                }
                default:
                    UNREACHABLE("process_int handles only ints");
                    break;
                }

                res[0] = put_into_assignment(out, is_private);
                return res;
            }

            bool take_int(llvm::Value *int_arg, const boost::json::object &value, bool is_private) {
                if (value.size() != 1 || !value.contains("int"))
                    return false;
                std::size_t bitness = int_arg->getType()->getPrimitiveSizeInBits();
                auto values = process_int(value, bitness, is_private);
                if (values.size() != 1)
                    return false;
                frame.scalars[int_arg] = values[0];
                return true;
            }

            bool take_vector(llvm::Value *vector_arg, llvm::Type *vector_type, const boost::json::object &value, bool is_private) {
                size_t arg_len = llvm::cast<llvm::FixedVectorType>(vector_type)->getNumElements();
                if (value.size() != 1 && !value.contains("vector")) {
                    return false;
                }
                frame.vectors[vector_arg] = process_vector(llvm::cast<llvm::FixedVectorType>(vector_type), value, is_private);
                return frame.vectors[vector_arg].size() > 0;
            }

            bool try_string(llvm::Value *arg, llvm::Type *arg_type, const boost::json::object &value, bool is_private) {
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
                auto pointer_var = put_into_assignment(ptr, is_private);
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

            bool try_struct(llvm::Value *arg, llvm::StructType *struct_type, const boost::json::object &value, bool is_private) {
                ptr_type ptr = memory.add_cells(layout_resolver.get_type_layout<BlueprintFieldType>(struct_type));
                process_struct(struct_type, value, ptr, is_private);
                auto variable = put_into_assignment(ptr, is_private);
                frame.scalars[arg] = variable;
                return true;
            }

            bool try_array(llvm::Value *arg, llvm::ArrayType *array_type, const boost::json::object &value, bool is_private) {
                ptr_type ptr = memory.add_cells(layout_resolver.get_type_layout<BlueprintFieldType>(array_type));
                process_array(array_type, value, ptr, is_private);
                auto variable = put_into_assignment(ptr, is_private);;
                frame.scalars[arg] = variable;
                return true;
            }

            ptr_type process_array(llvm::ArrayType *array_type, const boost::json::object &value, ptr_type ptr, bool is_private) {
                ASSERT(value.size() == 1 && value.contains("array"));
                ASSERT(value.at("array").is_array());
                auto &arr = value.at("array").as_array();
                ASSERT(array_type->getNumElements() == arr.size());
                for (size_t i = 0; i < array_type->getNumElements(); ++i) {
                    ptr = dispatch_type(array_type->getElementType(), arr[i], ptr, is_private);
                }
                return ptr;
            }

            ptr_type process_struct(llvm::StructType *struct_type, const boost::json::object &value, ptr_type ptr, bool is_private) {
                ASSERT(value.size() == 1);
                if (value.contains("array") && struct_type->getNumElements() == 1 &&
                    struct_type->getElementType(0)->isArrayTy()) {
                    // Assuming std::array
                    return process_array(llvm::cast<llvm::ArrayType>(struct_type->getElementType(0)), value, ptr, is_private);
                }
                ASSERT(value.contains("struct") && value.at("struct").is_array());
                auto &arr = value.at("struct").as_array();
                ASSERT(arr.size() == struct_type->getNumElements());
                for (unsigned i = 0; i < struct_type->getNumElements(); ++i) {
                    auto elem_ty = struct_type->getElementType(i);
                    ptr = dispatch_type(elem_ty, arr[i], ptr, is_private);
                }
                return ptr;
            }

            std::vector<var> process_vector(llvm::FixedVectorType *vector_type, const boost::json::object &value, bool is_private) {
                ASSERT(value.size() == 1 && value.contains("vector"));
                ASSERT(value.at("vector").is_array());
                auto &vec = value.at("vector").as_array();
                ASSERT(vector_type->getNumElements() == vec.size());
                std::vector<var> res;
                for (size_t i = 0; i < vector_type->getNumElements(); ++i) {
                    auto elem_vector = process_leaf_type(vector_type->getElementType(), vec[i].as_object(), is_private);
                    ASSERT(!elem_vector.empty());
                    res.insert(res.end(), elem_vector.begin(), elem_vector.end());
                }
                return res;
            }

            std::vector<var> process_leaf_type(llvm::Type *type, const boost::json::object &value, bool is_private) {
                switch (type->getTypeID()) {
                case llvm::Type::GaloisFieldTyID:
                    return process_field(llvm::cast<llvm::GaloisFieldType>(type), value, is_private);
                case llvm::Type::EllipticCurveTyID:
                    return process_curve(llvm::cast<llvm::EllipticCurveType>(type), value, is_private);
                case llvm::Type::IntegerTyID:
                    return process_int(value, type->getPrimitiveSizeInBits(), is_private);
                case llvm::Type::FixedVectorTyID:
                    return process_vector(llvm::cast<llvm::FixedVectorType>(type), value, is_private);
                default:
                    UNREACHABLE("Unexpected leaf type");
                }
            }

            ptr_type dispatch_type(llvm::Type *type, const boost::json::value &value, ptr_type ptr, bool is_private) {
                switch (type->getTypeID()) {
                case llvm::Type::GaloisFieldTyID:
                case llvm::Type::EllipticCurveTyID:
                case llvm::Type::IntegerTyID:
                case llvm::Type::FixedVectorTyID:{
                    auto flat_components = process_leaf_type(type, value.as_object(), is_private);
                    ASSERT(!flat_components.empty());
                    for (auto num : flat_components) {
                        memory.store(ptr++, num);
                    }
                    return ptr;
                }
                case llvm::Type::ArrayTyID:
                    return process_array(llvm::cast<llvm::ArrayType>(type), value.as_object(), ptr, is_private);
                case llvm::Type::StructTyID: {
                    return process_struct(llvm::cast<llvm::StructType>(type), value.as_object(), ptr, is_private);
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

                    bool is_private = current_arg->hasAttribute(llvm::Attribute::PrivateInput);

                    if (llvm::isa<llvm::PointerType>(arg_type)) {
                        if (current_arg->hasStructRetAttr()) {
                            auto pointee = current_arg->getAttribute(llvm::Attribute::StructRet).getValueAsType();
                            ptr_type ptr = memory.add_cells(layout_resolver.get_type_layout<BlueprintFieldType>(pointee));
                            frame.scalars[current_arg] = put_into_assignment(ptr, is_private);
                            ret_gap += 1;
                            continue;
                        }
                        if (current_arg->hasAttribute(llvm::Attribute::ByVal)) {
                            auto pointee = current_arg->getAttribute(llvm::Attribute::ByVal).getValueAsType();
                            if (pointee->isStructTy()) {
                                if (try_struct(current_arg, llvm::cast<llvm::StructType>(pointee), current_value, is_private))
                                    continue;
                            } else if (pointee->isArrayTy()) {
                                if (try_array(current_arg, llvm::cast<llvm::ArrayType>(pointee), current_value, is_private))
                                    continue;
                            } else {
                                UNREACHABLE("unsupported pointer type");
                            }
                        }
                        if (!try_string(current_arg, arg_type, current_value, is_private)) {
                            std::cerr << "Unhandled pointer argument" << std::endl;
                            return false;
                        }
                    } else if (llvm::isa<llvm::FixedVectorType>(arg_type)) {
                        if (!take_vector(current_arg, arg_type, current_value, is_private))
                            return false;
                    } else if (llvm::isa<llvm::EllipticCurveType>(arg_type)) {
                        if (!take_curve(current_arg, arg_type, current_value, is_private))
                            return false;
                    } else if (llvm::isa<llvm::GaloisFieldType>(arg_type)) {
                        if (!take_field(current_arg, arg_type, current_value, is_private))
                            return false;
                    } else if (llvm::isa<llvm::IntegerType>(arg_type)) {
                        if (!take_int(current_arg, current_value, is_private))
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
            size_t private_input_idx;
            std::string error;
        };
    }   // namespace blueprint
}    // namespace nil


#endif  // CRYPTO3_ASSIGNER_PUBLIC_INPUT_HPP
