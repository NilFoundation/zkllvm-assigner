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

#ifndef CRYPTO3_ASSIGNER_CURVES_INTRINSIC_CURVE25519_DOUBLING_HPP
#define CRYPTO3_ASSIGNER_CURVES_INTRINSIC_CURVE25519_DOUBLING_HPP

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
#include <nil/blueprint/components/algebra/fields/plonk/non_native/addition.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/multiplication.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/subtraction.hpp>

#include <nil/blueprint/stack.hpp>

namespace nil {
    namespace blueprint {
        template<typename BlueprintFieldType, typename ArithmetizationParams>
        void handle_assigner_curve25519_affine_double_component(
            const llvm::Instruction *inst,
            stack_frame<crypto3::zk::snark::plonk_variable<BlueprintFieldType>> &frame,
            circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
            assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignmnt,
            std::uint32_t start_row) {

                // P = 2*T
                // t0 = T_y * T_y
                // t1 = T_x * T_x
                // t2 = T_x * T_y
                // t3 = t0.output - t1.output  // TyTy - TxTx
                // t4 = t2.output + t2.output  // 2TxTy
                // t5 = t1.output + t0.output  // TxTx + TyTy
                // t6 = t1.output - t0.output  // TxTx - TyTy
                // t7 = P_x * t3.output        // Px * (TyTy - TxTx)
                // t8 = P_y + P_y              // 2Py
                // t9 = P_y * t6.output        // Py * (TxTx - TyTy)
                // t10 = t8.output + t9.output // Py(2 + TxTx - TyTy)

                // copy constraint (t4, t7)    // 2TxTy == Px * (TyTy - TxTx)
                // copy constraint (t5, t10)   // TxTx + TyTy == Py(2 + TxTx - TyTy)



            using add_component = components::addition<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                typename crypto3::algebra::fields::curve25519_base_field, 
                9, basic_non_native_policy<BlueprintFieldType>>;

            using mul_component = components::multiplication<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                typename crypto3::algebra::fields::curve25519_base_field, 9,
                basic_non_native_policy<BlueprintFieldType>>;

            using sub_component = components::subtraction<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                typename crypto3::algebra::fields::curve25519_base_field, 9,
                basic_non_native_policy<BlueprintFieldType>>;

            using var = crypto3::zk::snark::plonk_variable<BlueprintFieldType>;
            using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;
            using operating_field_type = crypto3::algebra::fields::curve25519_base_field;

            constexpr const std::int32_t ec_point_size = 2*4;
            constexpr const std::int32_t input_size = 2*ec_point_size + 4;

            auto &args = frame.vectors[inst->getOperand(0)];
            std::array<var, input_size> input_vars;
            std::copy(args.begin(), args.end(), input_vars.begin());

            // input: T_x, T_y, R_x, R_y
            typename non_native_policy_type::template field<operating_field_type>::value_type T_x = 
                {input_vars[ 0], input_vars[ 1], input_vars[ 2], input_vars[ 3]};
            typename non_native_policy_type::template field<operating_field_type>::value_type T_y = 
                {input_vars[ 4], input_vars[ 5], input_vars[ 6], input_vars[ 7]};

            mul_component mul_instance({0, 1, 2, 3, 4, 5, 6, 7, 8},{},{});
            add_component add_instance({0, 1, 2, 3, 4, 5, 6, 7, 8},{},{});
            sub_component sub_instance({0, 1, 2, 3, 4, 5, 6, 7, 8},{},{});

            typename BlueprintFieldType::integral_type base = 1;
            typename BlueprintFieldType::integral_type mask = (base << 66) - 1;


            std::array<typename BlueprintFieldType::value_type, 4> T_x_array = {
                var_value(assignmnt, T_x[0]), var_value(assignmnt, T_x[1]),
                var_value(assignmnt, T_x[2]), var_value(assignmnt, T_x[3])};
            std::array<typename BlueprintFieldType::value_type, 4> T_y_array = {
                var_value(assignmnt, T_y[0]), var_value(assignmnt, T_y[1]),
                var_value(assignmnt, T_y[2]), var_value(assignmnt, T_y[3])};

            typename crypto3::algebra::curves::ed25519::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type T(
                (typename crypto3::algebra::curves::ed25519::base_field_type::integral_type(T_x_array[0].data) +
                 typename crypto3::algebra::curves::ed25519::base_field_type::integral_type(T_x_array[1].data) * (base << 66) +
                 typename crypto3::algebra::curves::ed25519::base_field_type::integral_type(T_x_array[2].data) * (base << 132) +
                 typename crypto3::algebra::curves::ed25519::base_field_type::integral_type(T_x_array[3].data) * (base << 198)),
                (typename crypto3::algebra::curves::ed25519::base_field_type::integral_type(T_y_array[0].data) +
                 typename crypto3::algebra::curves::ed25519::base_field_type::integral_type(T_y_array[1].data) * (base << 66) +
                 typename crypto3::algebra::curves::ed25519::base_field_type::integral_type(T_y_array[2].data) * (base << 132) +
                 typename crypto3::algebra::curves::ed25519::base_field_type::integral_type(T_y_array[3].data) * (base << 198)));
            
            typename crypto3::algebra::curves::ed25519::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type P = T + T;

            typename BlueprintFieldType::extended_integral_type P_x_value = typename BlueprintFieldType::extended_integral_type(P.X.data);
            typename BlueprintFieldType::extended_integral_type P_y_value = typename BlueprintFieldType::extended_integral_type(P.Y.data);

            std::array<typename BlueprintFieldType::integral_type, 4> P_x_chunk;
            P_x_chunk[0] = typename BlueprintFieldType::integral_type((P_x_value       ) & (mask));
            P_x_chunk[1] = typename BlueprintFieldType::integral_type((P_x_value >>  66) & (mask));
            P_x_chunk[2] = typename BlueprintFieldType::integral_type((P_x_value >> 132) & (mask));
            P_x_chunk[3] = typename BlueprintFieldType::integral_type((P_x_value >> 198) & (mask));

            std::array<typename BlueprintFieldType::integral_type, 4> P_y_chunk;
            P_y_chunk[0] = typename BlueprintFieldType::integral_type((P_y_value       ) & (mask));
            P_y_chunk[1] = typename BlueprintFieldType::integral_type((P_y_value >>  66) & (mask));
            P_y_chunk[2] = typename BlueprintFieldType::integral_type((P_y_value >> 132) & (mask));
            P_y_chunk[3] = typename BlueprintFieldType::integral_type((P_y_value >> 198) & (mask));

            
            assignmnt.witness(mul_instance.W(0), start_row + 1) = P_x_chunk[0];
            assignmnt.witness(mul_instance.W(1), start_row + 1) = P_x_chunk[1];
            assignmnt.witness(mul_instance.W(2), start_row + 1) = P_x_chunk[2];
            assignmnt.witness(mul_instance.W(3), start_row + 1) = P_x_chunk[3];

            assignmnt.witness(mul_instance.W(0), start_row + 2) = P_y_chunk[0];
            assignmnt.witness(mul_instance.W(1), start_row + 2) = P_y_chunk[1];
            assignmnt.witness(mul_instance.W(2), start_row + 2) = P_y_chunk[2];
            assignmnt.witness(mul_instance.W(3), start_row + 2) = P_y_chunk[3];

            std::array <var, 4> P_x = {var(mul_instance.W(0), start_row + 1, false), var(mul_instance.W(1), start_row + 1, false),
                                       var(mul_instance.W(2), start_row + 1, false), var(mul_instance.W(3), start_row + 1, false)};
            

            std::array <var, 4> P_y = {var(mul_instance.W(0), start_row + 2, false), var(mul_instance.W(1), start_row + 2, false),
                                       var(mul_instance.W(2), start_row + 2, false), var(mul_instance.W(3), start_row + 2, false)};
            
            start_row = assignmnt.allocated_rows();


            typename mul_component::input_type t0_inp = {T_x, T_y};
            components::generate_circuit(mul_instance, bp, assignmnt, t0_inp, start_row);
            typename mul_component::result_type t0_res = 
                components::generate_assignments(mul_instance, assignmnt, t0_inp, start_row);
            start_row = assignmnt.allocated_rows();

            typename mul_component::input_type t1_inp = {T_y, T_x};
            components::generate_circuit(mul_instance, bp, assignmnt, t1_inp, start_row);
            typename mul_component::result_type t1_res = 
                components::generate_assignments(mul_instance, assignmnt, t1_inp, start_row);
            start_row = assignmnt.allocated_rows();

            typename mul_component::input_type t2_inp = {T_x, T_y};
            components::generate_circuit(mul_instance, bp, assignmnt, t2_inp, start_row);
            typename mul_component::result_type t2_res = 
                components::generate_assignments(mul_instance, assignmnt, t2_inp, start_row);
            start_row = assignmnt.allocated_rows();

            typename sub_component::input_type t3_inp = {t0_res.output, t1_res.output};
            components::generate_circuit(sub_instance, bp, assignmnt, t3_inp, start_row);
            typename sub_component::result_type t3_res = 
                components::generate_assignments(sub_instance, assignmnt, t3_inp, start_row);
            start_row = assignmnt.allocated_rows();



            typename add_component::input_type t4_inp = {t2_res.output, t2_res.output};
            components::generate_circuit(add_instance, bp, assignmnt, t4_inp, start_row);
            typename add_component::result_type t4_res = 
                components::generate_assignments(add_instance, assignmnt, t4_inp, start_row);
            start_row = assignmnt.allocated_rows();

            typename add_component::input_type t5_inp = {t1_res.output, t0_res.output};
            components::generate_circuit(add_instance, bp, assignmnt, t5_inp, start_row);
            typename add_component::result_type t5_res = 
                components::generate_assignments(add_instance, assignmnt, t5_inp, start_row);
            start_row = assignmnt.allocated_rows();

            typename sub_component::input_type t6_inp = {t1_res.output, t0_res.output};
            components::generate_circuit(sub_instance, bp, assignmnt, t6_inp, start_row);
            typename sub_component::result_type t6_res = 
                components::generate_assignments(sub_instance, assignmnt, t6_inp, start_row);
            start_row = assignmnt.allocated_rows();

            typename mul_component::input_type t7_inp = {P_x, t3_res.output};
            components::generate_circuit(mul_instance, bp, assignmnt, t7_inp, start_row);
            typename mul_component::result_type t7_res = 
                components::generate_assignments(mul_instance, assignmnt, t7_inp, start_row);
            start_row = assignmnt.allocated_rows();

            typename add_component::input_type t8_inp = {P_y, P_y};
            components::generate_circuit(add_instance, bp, assignmnt, t8_inp, start_row);
            typename add_component::result_type t8_res = 
                components::generate_assignments(add_instance, assignmnt, t8_inp, start_row);
            start_row = assignmnt.allocated_rows();

            typename mul_component::input_type t9_inp = {P_y, t6_res.output};
            components::generate_circuit(mul_instance, bp, assignmnt, t9_inp, start_row);
            typename mul_component::result_type t9_res = 
                components::generate_assignments(mul_instance, assignmnt, t9_inp, start_row);
            start_row = assignmnt.allocated_rows();

            typename add_component::input_type t10_inp = {t8_res.output, t9_res.output};
            components::generate_circuit(add_instance, bp, assignmnt, t10_inp, start_row);
            typename add_component::result_type t10_res = 
                components::generate_assignments(add_instance, assignmnt, t10_inp, start_row);
            start_row = assignmnt.allocated_rows();

            for (std::size_t i = 0; i < 4; i++) {
                bp.add_copy_constraint({{t4_res.output[i].index, t4_res.output[i].rotation, false},
                                        {t7_res.output[i].index, t7_res.output[i].rotation, false}});
                
                bp.add_copy_constraint({{t5_res.output[i].index, t5_res.output[i].rotation, false},
                                        {t10_res.output[i].index, t10_res.output[i].rotation, false}});
            }

            frame.vectors[inst] = {P_x[0], P_x[1], P_x[2], P_x[3],
                                   P_y[0], P_y[1], P_y[2], P_y[3]};

        }
    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_CURVES_INTRINSIC_CURVE25519_DOUBLING_HPP
