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
        struct field_size_struct;

        template<>
        struct field_size_struct<typename nil::crypto3::algebra::curves::pallas::base_field_type> {
            using BlueprintFieldType = nil::crypto3::algebra::curves::pallas::base_field_type;

            constexpr static const std::size_t base_pallas =
                nil::blueprint::detail::basic_non_native_policy_field_type<BlueprintFieldType,
                typename nil::crypto3::algebra::curves::pallas::base_field_type>::ratio;
            constexpr static const std::size_t scalar_pallas =
                nil::blueprint::detail::basic_non_native_policy_field_type<BlueprintFieldType,
                typename nil::crypto3::algebra::curves::pallas::scalar_field_type>::ratio;
            constexpr static const std::size_t base_25519 =
                nil::blueprint::detail::basic_non_native_policy_field_type<BlueprintFieldType,
                typename nil::crypto3::algebra::curves::ed25519::base_field_type>::ratio;
            constexpr static const std::size_t scalar_25519 =
                nil::blueprint::detail::basic_non_native_policy_field_type<BlueprintFieldType,
                typename nil::crypto3::algebra::curves::ed25519::scalar_field_type>::ratio;
            constexpr static const std::size_t base_12381 = 0;
            constexpr static const std::size_t scalar_12381 = 0;
            constexpr static const std::size_t base_vesta = 0;
            constexpr static const std::size_t scalar_vesta = 0;
        };


        template<>
        struct field_size_struct<typename nil::crypto3::algebra::fields::bls12_base_field<381>> {
            using BlueprintFieldType = nil::crypto3::algebra::fields::bls12_base_field<381>;

            constexpr static const std::size_t base_pallas = 0;
            constexpr static const std::size_t scalar_pallas = 0;
            constexpr static const std::size_t base_25519 = 0;
            constexpr static const std::size_t scalar_25519 = 0;
            constexpr static const std::size_t base_12381 =
                nil::blueprint::detail::basic_non_native_policy_field_type<BlueprintFieldType,
                typename nil::crypto3::algebra::fields::bls12_base_field<381>>::ratio;
            constexpr static const std::size_t scalar_12381 =
                nil::blueprint::detail::basic_non_native_policy_field_type<BlueprintFieldType,
                typename nil::crypto3::algebra::fields::bls12_scalar_field<381>>::ratio;
            constexpr static const std::size_t base_vesta = 0;
            constexpr static const std::size_t scalar_vesta = 0;


        };

        template<typename BlueprintFieldType>
        std::size_t field_kind_size (llvm::GaloisFieldKind field_kind) {

            std::size_t size = 0;

            switch (field_kind) {
                case llvm::GALOIS_FIELD_PALLAS_BASE: {
                    size = field_size_struct<BlueprintFieldType>::base_pallas;
                    break;
                }
                case llvm::GALOIS_FIELD_PALLAS_SCALAR: {
                    size = field_size_struct<BlueprintFieldType>::scalar_pallas;
                    break;
                }
                case llvm::GALOIS_FIELD_VESTA_BASE: {
                    size = field_size_struct<BlueprintFieldType>::base_vesta;
                    break;
                }
                case llvm::GALOIS_FIELD_VESTA_SCALAR: {
                    size = field_size_struct<BlueprintFieldType>::scalar_vesta;
                    break;
                }
                case llvm::GALOIS_FIELD_BLS12381_BASE: {
                    size = field_size_struct<BlueprintFieldType>::base_12381;
                    break;
                }
                case llvm::GALOIS_FIELD_BLS12381_SCALAR: {
                    size = field_size_struct<BlueprintFieldType>::scalar_12381;
                    break;
                }
                case llvm::GALOIS_FIELD_CURVE25519_BASE: {
                    size = field_size_struct<BlueprintFieldType>::base_25519;
                    break;
                }
                case llvm::GALOIS_FIELD_CURVE25519_SCALAR: {
                    size = field_size_struct<BlueprintFieldType>::scalar_25519;
                    break;
                }

                default: {
                    UNREACHABLE("unsupported field operand type");
                    break;
                }

            }
            ASSERT_MSG(size != 0, "Field type is not supported for used native field yet");
            return size;

        }

        template<typename BlueprintFieldType>
        std::size_t field_arg_num(llvm::Type *arg_type) {
            if(arg_type->isIntegerTy()) {
                return 1;
            }
            ASSERT_MSG(llvm::isa<llvm::GaloisFieldType>(arg_type), "only fields can be handled here");
            return field_kind_size<BlueprintFieldType>(llvm::cast<llvm::GaloisFieldType>(arg_type)->getFieldKind());
        }

        template<typename BlueprintFieldType>
        std::size_t curve_arg_num(llvm::Type *arg_type) {
            ASSERT_MSG(llvm::isa<llvm::EllipticCurveType>(arg_type), "only curves can be handled here");
            bool is_bls = std::is_same<BlueprintFieldType, typename nil::crypto3::algebra::curves::bls12<381>::base_field_type>::value;

            switch (llvm::cast<llvm::EllipticCurveType>(arg_type)->getCurveKind()) {
                case llvm::ELLIPTIC_CURVE_BLS12381_G2: {
                    ASSERT_MSG(is_bls, "g2 type is defined only for native bls12381 base field");
                    return 4;
                }
                case llvm::ELLIPTIC_CURVE_BLS12381_GT: {
                    ASSERT_MSG(is_bls, "gt type is defined only for native bls12381 base field");
                    return 12;
                }

                default:
                    return 2 * field_kind_size<BlueprintFieldType>(llvm::cast<llvm::EllipticCurveType>(arg_type)->GetBaseFieldKind());
            };
        }

        template<typename BlueprintFieldType, typename NonNativeFieldType>
        std::vector<typename BlueprintFieldType::value_type> value_into_vector (typename NonNativeFieldType::value_type input) {
            using non_native_policy = typename nil::blueprint::detail::basic_non_native_policy_field_type<BlueprintFieldType, NonNativeFieldType>;

            if constexpr (non_native_policy::ratio == 0) {
                UNREACHABLE("non_native_policy is not implemented yet");
            }
            else {
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

        }

        template<typename BlueprintFieldType, typename NonNativeFieldType>
        typename NonNativeFieldType::value_type vector_into_value (std::vector<typename BlueprintFieldType::value_type> input) {
            using non_native_policy = typename nil::blueprint::detail::basic_non_native_policy_field_type<BlueprintFieldType, NonNativeFieldType>;

            if (input.size() != non_native_policy::ratio) {
                std::cerr << "input.size(): " << input.size() << "\n";
                std::cerr << "non_native_policy::ratio: " << non_native_policy::ratio << "\n";
                UNREACHABLE("input.size() != non_native_policy::ratio");
            }

            if constexpr (non_native_policy::ratio == 0) {
                UNREACHABLE("non_native_policy is not implemented yet");
            }
            else {
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
                case llvm::GALOIS_FIELD_BLS12381_BASE: {
                    using non_native_field_type = typename nil::crypto3::algebra::fields::bls12_base_field<381>;
                    return check_modulus_and_chop<BlueprintFieldType, non_native_field_type>(glued_non_native);
                }
                case llvm::GALOIS_FIELD_BLS12381_SCALAR: {
                    using non_native_field_type = typename nil::crypto3::algebra::fields::bls12_scalar_field<381>;
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
                    case llvm::GALOIS_FIELD_BLS12381_BASE: {
                        using operating_field_type = typename nil::crypto3::algebra::curves::bls12<381>::base_field_type;
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
                case llvm::GALOIS_FIELD_BLS12381_BASE: {
                    using operating_field_type = typename nil::crypto3::algebra::curves::bls12<381>::base_field_type;
                    return typename BlueprintFieldType::integral_type(vector_into_value<BlueprintFieldType, operating_field_type>(input).data);
                }
                default:
                    UNREACHABLE("unsupported field operand type");
            }
        }
    }    // namespace blueprint
}    // namespace nil

#endif  // CRYPTO3_ASSIGNER_NON_NATIVE_MARSHALLING_HPP
