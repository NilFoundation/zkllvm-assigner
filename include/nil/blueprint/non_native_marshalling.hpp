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

#ifndef CRYPTO3_ASSIGNER_NON_NATIVE_MARSHALLING_HPP
#define CRYPTO3_ASSIGNER_NON_NATIVE_MARSHALLING_HPP

namespace nil {
    namespace blueprint {

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


        template<typename BlueprintFieldType, typename NonNativeFieldType>
        std::vector<typename BlueprintFieldType::value_type> value_into_vector (typename NonNativeFieldType::value_type input) {
            using non_native_policy = typename nil::blueprint::detail::basic_non_native_policy_field_type<BlueprintFieldType, NonNativeFieldType>;

            if constexpr (non_native_policy::ratio == 1) {
                std::vector<typename BlueprintFieldType::value_type> res;
                res.push_back(typename BlueprintFieldType::value_type(typename BlueprintFieldType::integral_type(input.data)));
                return res;
            }
            else {
                auto res_arr = non_native_policy::chop_non_native(input);
                return std::vector<typename BlueprintFieldType::value_type>(std::begin(res_arr), std::end(res_arr));
            }
        }

        template<typename BlueprintFieldType, typename NonNativeFieldType>
        typename NonNativeFieldType::value_type vector_into_value (std::vector<typename BlueprintFieldType::value_type> input) {
            using non_native_policy = typename nil::blueprint::detail::basic_non_native_policy_field_type<BlueprintFieldType, NonNativeFieldType>;

            if (input.size() != non_native_policy::ratio) {
                std::cerr << "input.size(): " << input.size() << "\n";
                std::cerr << "non_native_policy::ratio: " << non_native_policy::ratio << "\n";
                UNREACHABLE("input.size() != non_native_policy::ratio");
            }


            if constexpr (non_native_policy::ratio == 1) {
                UNREACHABLE("scalar, no need to use vector, conversion for ratio==1 is not implemented");
            }
            else {
                typename non_native_policy::chopped_value_type chopped_field;
                for (std::size_t i = 0; i < non_native_policy::ratio; i++) {
                    chopped_field[i] = input[i];
                }
                typename NonNativeFieldType::value_type res = non_native_policy::glue_non_native(chopped_field);
                return res;
            }
        }

        template<typename BlueprintFieldType, typename NonNativeFieldType>
        std::vector<typename BlueprintFieldType::value_type> check_modulus_and_chop(typename BlueprintFieldType::extended_integral_type glued_non_native) {
            if(glued_non_native >= NonNativeFieldType::modulus) {
                std::cerr << std::hex;
                std::cerr << "0x" << glued_non_native << " >=\n";
                std::cerr << "0x" << NonNativeFieldType::modulus << "\n";
                UNREACHABLE("value does not fit into field modulus!");
            }
            return value_into_vector<BlueprintFieldType, NonNativeFieldType>(typename NonNativeFieldType::value_type(glued_non_native));
        }


        template<typename BlueprintFieldType>
        std::vector<typename BlueprintFieldType::value_type> extended_integral_into_vector (llvm::GaloisFieldKind arg_field_type, typename BlueprintFieldType::extended_integral_type glued_non_native) {
            switch (arg_field_type) {
                case llvm::GALOIS_FIELD_CURVE25519_BASE: {
                    using non_native_field_type = typename nil::crypto3::algebra::curves::ed25519::base_field_type;
                    return check_modulus_and_chop<BlueprintFieldType, non_native_field_type>(glued_non_native);
                }
                case llvm::GALOIS_FIELD_CURVE25519_SCALAR: {
                    using non_native_field_type = typename nil::crypto3::algebra::curves::ed25519::scalar_field_type;
                    return check_modulus_and_chop<BlueprintFieldType, non_native_field_type>(glued_non_native);
                }
                case llvm::GALOIS_FIELD_PALLAS_BASE: {
                    using non_native_field_type = typename nil::crypto3::algebra::curves::pallas::base_field_type;
                    return check_modulus_and_chop<BlueprintFieldType, non_native_field_type>(glued_non_native);
                }
                case llvm::GALOIS_FIELD_PALLAS_SCALAR: {
                    using non_native_field_type = typename nil::crypto3::algebra::curves::pallas::scalar_field_type;
                    return check_modulus_and_chop<BlueprintFieldType, non_native_field_type>(glued_non_native);
                }

                default:
                    UNREACHABLE("unsupported field operand type");
            }
        }
        template<typename FieldType, typename BlueprintFieldType>
        std::vector<typename BlueprintFieldType::value_type> field_dependent_marshal_val(const llvm::Value *val) {
            ASSERT(llvm::isa<llvm::ConstantField>(val) || llvm::isa<llvm::ConstantInt>(val));
            llvm::APInt int_val;
            if (llvm::isa<llvm::ConstantField>(val)) {
                int_val = llvm::cast<llvm::ConstantField>(val)->getValue();
            } else {
                int_val = llvm::cast<llvm::ConstantInt>(val)->getValue();
            }
            unsigned words = int_val.getNumWords();
            typename FieldType::value_type field_constant;
            if (words == 1) {
                field_constant = int_val.getSExtValue();
            } else {
                // TODO(maksenov): avoid copying here
                const char *APIntData = reinterpret_cast<const char *>(int_val.getRawData());
                std::vector<char> bytes(APIntData, APIntData + words * 8);
                using marshalling_field_element = nil::crypto3::marshalling::types::field_element<
                    nil::marshalling::field_type<nil::marshalling::option::little_endian>,
                    nil::crypto3::algebra::fields::pallas_base_field::value_type>;
                auto iter = bytes.cbegin();
                field_constant = nil::crypto3::marshalling::processing::read_data<
                    typename marshalling_field_element::value_type,
                    typename marshalling_field_element::endian_type>(iter, bytes.size() * 8);    // size in bits
            }
            return value_into_vector<BlueprintFieldType, FieldType>(field_constant);
        }

        template <typename BlueprintFieldType>
        std::vector<typename BlueprintFieldType::value_type> marshal_field_val(const llvm::Value *val) {

            ASSERT(llvm::isa<llvm::ConstantField>(val) || llvm::isa<llvm::ConstantInt>(val));
            if (llvm::isa<llvm::ConstantInt>(val)) {
                return field_dependent_marshal_val<BlueprintFieldType, BlueprintFieldType>(val);
            } else {
                switch (llvm::cast<llvm::GaloisFieldType>(val->getType())->getFieldKind()) {
                    case llvm::GALOIS_FIELD_CURVE25519_BASE: {
                        using operating_field_type = typename nil::crypto3::algebra::curves::ed25519::base_field_type;
                        return field_dependent_marshal_val<operating_field_type, BlueprintFieldType>(val);
                    }
                    case llvm::GALOIS_FIELD_CURVE25519_SCALAR: {
                        using operating_field_type = typename nil::crypto3::algebra::curves::ed25519::scalar_field_type;
                        return field_dependent_marshal_val<operating_field_type, BlueprintFieldType>(val);
                    }
                    case llvm::GALOIS_FIELD_PALLAS_BASE: {
                        using operating_field_type = typename nil::crypto3::algebra::curves::pallas::base_field_type;
                        return field_dependent_marshal_val<operating_field_type, BlueprintFieldType>(val);
                    }
                    case llvm::GALOIS_FIELD_PALLAS_SCALAR: {
                        using operating_field_type = typename nil::crypto3::algebra::curves::pallas::scalar_field_type;
                        return field_dependent_marshal_val<operating_field_type, BlueprintFieldType>(val);
                    }
                    default:
                        UNREACHABLE("unsupported field operand type");
                }
            }
        }

        template <typename BlueprintFieldType>
        typename BlueprintFieldType::integral_type unmarshal_field_val(const llvm::GaloisFieldKind field_type, std::vector<typename BlueprintFieldType::value_type> input) {
            switch (field_type) {
                case llvm::GALOIS_FIELD_CURVE25519_BASE: {
                    using operating_field_type = typename nil::crypto3::algebra::curves::ed25519::base_field_type;
                    return typename BlueprintFieldType::integral_type(vector_into_value<BlueprintFieldType, operating_field_type>(input).data);
                }
                case llvm::GALOIS_FIELD_CURVE25519_SCALAR: {
                    using operating_field_type = typename nil::crypto3::algebra::curves::ed25519::scalar_field_type;
                    return typename BlueprintFieldType::integral_type(vector_into_value<BlueprintFieldType, operating_field_type>(input).data);
                }
                case llvm::GALOIS_FIELD_PALLAS_BASE: {
                    using operating_field_type = typename nil::crypto3::algebra::curves::pallas::base_field_type;
                    return typename BlueprintFieldType::integral_type(vector_into_value<BlueprintFieldType, operating_field_type>(input).data);
                }
                case llvm::GALOIS_FIELD_PALLAS_SCALAR: {
                    using operating_field_type = typename nil::crypto3::algebra::curves::pallas::scalar_field_type;
                    return typename BlueprintFieldType::integral_type(vector_into_value<BlueprintFieldType, operating_field_type>(input).data);
                }
                default:
                    UNREACHABLE("unsupported field operand type");
            }
        }
    }    // namespace blueprint
}    // namespace nil

#endif  // CRYPTO3_ASSIGNER_NON_NATIVE_MARSHALLING_HPP
