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

#ifndef CRYPTO3_ASSIGNER_FIELD_ADDITION_HPP
#define CRYPTO3_ASSIGNER_FIELD_ADDITION_HPP

#include "llvm/IR/Type.h"
#include "llvm/IR/TypeFinder.h"
#include "llvm/IR/TypedPointerType.h"

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/curves/curve25519.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/component.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/addition.hpp>
#include <nil/blueprint/components/non_native/algebra/fields/plonk/addition.hpp>

namespace nil {
    namespace blueprint {
        namespace detail {

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            components::component<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                make_native_field_addition_component(){

                using component_type = components::addition<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                        BlueprintFieldType, 3>;
                return component_type ({0, 1, 2}, {}, {});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename OperatingFieldType>
            components::component<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                make_non_native_field_addition_component(){

                using component_type = components::addition<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                        OperatingFieldType, 9>;
                return component_type ({0, 1, 2, 3, 4, 5, 6, 7, 8}, {}, {});
            }

        }    // namespace detail

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        components::component<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
            make_field_addition_component(llvm::Type* operand_type){

            components::component<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                component_instance;

            switch (llvm::cast<llvm::GaloisFieldType>(operand_type)->getFieldKind()) {
                case llvm::GALOIS_FIELD_BLS12_381_BASE: {
                    using operating_field_type = typename crypto3::algebra::curves::bls12<381>::base_field_type;

                    if (std::is_same<BlueprintFieldType, operating_field_type>::value){
                        component_instance =
                            detail::make_native_field_addition_component<BlueprintFieldType, ArithmetizationParams>();
                    }else{
                        component_instance =
                            detail::make_non_native_field_addition_component<BlueprintFieldType, ArithmetizationParams,
                                operating_field_type>();
                    }

                    break;
                }
                case llvm::GALOIS_FIELD_PALLAS_BASE: {
                    using operating_field_type = typename crypto3::algebra::curves::pallas::base_field_type;

                    if (std::is_same<BlueprintFieldType, operating_field_type>::value){
                        component_instance =
                            detail::make_native_field_addition_component<BlueprintFieldType, ArithmetizationParams>();
                    }else{
                        component_instance =
                            detail::make_non_native_field_addition_component<BlueprintFieldType, ArithmetizationParams,
                                operating_field_type>();
                    }

                    break;
                }
                case llvm::GALOIS_FIELD_CURVE_25519_BASE:{
                    using operating_field_type = typename crypto3::algebra::curves::ed25519::base_field_type;

                    if (std::is_same<BlueprintFieldType, operating_field_type>::value){
                        component_instance =
                            detail::make_native_field_addition_component<BlueprintFieldType, ArithmetizationParams>();
                    }else{
                        component_instance =
                            detail::make_non_native_field_addition_component<BlueprintFieldType, ArithmetizationParams,
                                operating_field_type>();
                    }

                    break;
                }
                default:
                    assert(1 == 0 && "unsupported field operand type");
            };

            return component_instance;
        }

    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_FIELD_ADDITION_HPP
