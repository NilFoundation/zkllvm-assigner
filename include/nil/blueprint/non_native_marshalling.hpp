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

    }    // namespace blueprint
}    // namespace nil

#endif  // CRYPTO3_ASSIGNER_NON_NATIVE_MARSHALLING_HPP
