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

#ifndef CRYPTO3_ASSIGNER_CURVES_INTRINSIC_CURVE25519_ADDITION_HPP
#define CRYPTO3_ASSIGNER_CURVES_INTRINSIC_CURVE25519_ADDITION_HPP

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
        void handle_assigner_curve25519_affine_addition_component(
            const llvm::Instruction *inst,
            stack_frame<crypto3::zk::snark::plonk_variable<BlueprintFieldType>> &frame,
            circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
            assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignmnt,
            std::uint32_t start_row) {

                // P = T * R
                // t0 = T_x * Ry;
                // t1 = T_y * R_x
                // t2 = T_x * R_x
                // t3 = T_y * R_y
                // z0 = t0.output + t1.output // T_x * R_y + T_y * R_x
                // z1 = t2.output + t3.output // T_x * R_x + T_y * R_y
                // z2 = t0.output * t1.output
                // d = 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3_cppui256
                // k0 = d_var_array * z2.output
                // k1 = P_x * k0.output
                // k2 = P_y * k0.output
                // k3 = P_x + k1.output
                // k4 = P_y - k2.output
                // copy_constraint(k3, z0) // Px * (1 + Tx*Ty*Rx*Ry) == Tx*Ry + Ty*Rx 
                // copy_constraint(k4, z1) // py * (1 - Tx*Ty*Rx*Ry) == Tx*Rx + Ty*Ry

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
            typename non_native_policy_type::template field<operating_field_type>::value_type R_x = 
                {input_vars[ 8], input_vars[ 8], input_vars[ 9], input_vars[10]};
            typename non_native_policy_type::template field<operating_field_type>::value_type R_y = 
                {input_vars[12], input_vars[13], input_vars[14], input_vars[15]};


            mul_component mul_instance({0, 1, 2, 3, 4, 5, 6, 7, 8},{},{});
            add_component add_instance({0, 1, 2, 3, 4, 5, 6, 7, 8},{},{});
            sub_component sub_instance({0, 1, 2, 3, 4, 5, 6, 7, 8},{},{});

            typename mul_component::input_type t0_inp = {T_x, R_y};
            components::generate_circuit(mul_instance, bp, assignmnt, t0_inp, start_row);
            typename mul_component::result_type t0_res = 
                components::generate_assignments(mul_instance, assignmnt, t0_inp, start_row);
            start_row = assignmnt.allocated_rows();

            typename mul_component::input_type t1_inp = {T_y, R_x};
            components::generate_circuit(mul_instance, bp, assignmnt, t1_inp, start_row);
            typename mul_component::result_type t1_res = 
                components::generate_assignments(mul_instance, assignmnt, t1_inp, start_row);
            start_row = assignmnt.allocated_rows();

            typename mul_component::input_type t2_inp = {T_x, R_x};
            components::generate_circuit(mul_instance, bp, assignmnt, t2_inp, start_row);
            typename mul_component::result_type t2_res = 
                components::generate_assignments(mul_instance, assignmnt, t2_inp, start_row);
            start_row = assignmnt.allocated_rows();

            typename mul_component::input_type t3_inp = {T_y, R_y};
            components::generate_circuit(mul_instance, bp, assignmnt, t3_inp, start_row);
            typename mul_component::result_type t3_res = 
                components::generate_assignments(mul_instance, assignmnt, t3_inp, start_row);
            start_row = assignmnt.allocated_rows();


                

            typename add_component::input_type z0_inp = {t0_res.output, t1_res.output};
            components::generate_circuit(add_instance, bp, assignmnt, z0_inp, start_row);
            typename add_component::result_type z0_res = 
                components::generate_assignments(add_instance, assignmnt, z0_inp, start_row);
            start_row = assignmnt.allocated_rows();

            typename add_component::input_type z1_inp = {t2_res.output, t3_res.output};
            components::generate_circuit(add_instance, bp, assignmnt, z1_inp, start_row);
            typename add_component::result_type z1_res = 
                components::generate_assignments(add_instance, assignmnt, z1_inp, start_row);
            start_row = assignmnt.allocated_rows();

            typename mul_component::input_type z2_inp = {t0_res.output, t1_res.output};
            components::generate_circuit(mul_instance, bp, assignmnt, z2_inp, start_row);
            typename mul_component::result_type z2_res = 
                components::generate_assignments(mul_instance, assignmnt, z2_inp, start_row);
            start_row = assignmnt.allocated_rows();



            typename BlueprintFieldType::extended_integral_type d_value = 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3_cppui256;
            typename BlueprintFieldType::integral_type base = 1;
            typename BlueprintFieldType::integral_type mask = (base << 66) - 1;

            std::array<typename BlueprintFieldType::integral_type, 4> d_chunk;
            d_chunk[0] = typename BlueprintFieldType::integral_type((d_value       ) & (mask));
            d_chunk[1] = typename BlueprintFieldType::integral_type((d_value >>  66) & (mask));
            d_chunk[2] = typename BlueprintFieldType::integral_type((d_value >> 132) & (mask));
            d_chunk[3] = typename BlueprintFieldType::integral_type((d_value >> 198) & (mask));

            assignmnt.witness(mul_instance.W(0), start_row) = d_chunk[0];
            assignmnt.witness(mul_instance.W(1), start_row) = d_chunk[1];
            assignmnt.witness(mul_instance.W(2), start_row) = d_chunk[2];
            assignmnt.witness(mul_instance.W(3), start_row) = d_chunk[3];

            std::array <var, 4> d_vars = {var(mul_instance.W(0), start_row, false), var(mul_instance.W(1), start_row, false),
                                          var(mul_instance.W(2), start_row, false), var(mul_instance.W(3), start_row, false)};
            


            std::array<typename BlueprintFieldType::value_type, 4> T_x_array = {
                var_value(assignmnt, T_x[0]), var_value(assignmnt, T_x[1]),
                var_value(assignmnt, T_x[2]), var_value(assignmnt, T_x[3])};
            std::array<typename BlueprintFieldType::value_type, 4> T_y_array = {
                var_value(assignmnt, T_y[0]), var_value(assignmnt, T_y[1]),
                var_value(assignmnt, T_y[2]), var_value(assignmnt, T_y[3])};

            std::array<typename BlueprintFieldType::value_type, 4> R_x_array = {
                var_value(assignmnt, R_x[0]), var_value(assignmnt, R_x[1]),
                var_value(assignmnt, R_x[2]), var_value(assignmnt, R_x[3])};
            std::array<typename BlueprintFieldType::value_type, 4> R_y_array = {
                var_value(assignmnt, R_y[0]), var_value(assignmnt, R_y[1]),
                var_value(assignmnt, R_y[2]), var_value(assignmnt, R_y[3])};

            typename crypto3::algebra::curves::ed25519::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type T(
                (typename crypto3::algebra::curves::ed25519::base_field_type::integral_type(T_x_array[0].data) +
                 typename crypto3::algebra::curves::ed25519::base_field_type::integral_type(T_x_array[1].data) * (base << 66) +
                 typename crypto3::algebra::curves::ed25519::base_field_type::integral_type(T_x_array[2].data) * (base << 132) +
                 typename crypto3::algebra::curves::ed25519::base_field_type::integral_type(T_x_array[3].data) * (base << 198)),
                (typename crypto3::algebra::curves::ed25519::base_field_type::integral_type(T_y_array[0].data) +
                 typename crypto3::algebra::curves::ed25519::base_field_type::integral_type(T_y_array[1].data) * (base << 66) +
                 typename crypto3::algebra::curves::ed25519::base_field_type::integral_type(T_y_array[2].data) * (base << 132) +
                 typename crypto3::algebra::curves::ed25519::base_field_type::integral_type(T_y_array[3].data) * (base << 198)));
            typename crypto3::algebra::curves::ed25519::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type R(
                (typename crypto3::algebra::curves::ed25519::base_field_type::integral_type(R_x_array[0].data) +
                 typename crypto3::algebra::curves::ed25519::base_field_type::integral_type(R_x_array[1].data) * (base << 66) +
                 typename crypto3::algebra::curves::ed25519::base_field_type::integral_type(R_x_array[2].data) * (base << 132) +
                 typename crypto3::algebra::curves::ed25519::base_field_type::integral_type(R_x_array[3].data) * (base << 198)),
                (typename crypto3::algebra::curves::ed25519::base_field_type::integral_type(R_y_array[0].data) +
                 typename crypto3::algebra::curves::ed25519::base_field_type::integral_type(R_y_array[1].data) * (base << 66) +
                 typename crypto3::algebra::curves::ed25519::base_field_type::integral_type(R_y_array[2].data) * (base << 132) +
                 typename crypto3::algebra::curves::ed25519::base_field_type::integral_type(R_y_array[3].data) * (base << 198)));

            typename crypto3::algebra::curves::ed25519::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type P = T + R;

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

            typename mul_component::input_type k0_inp = {d_vars, z2_res.output};
            components::generate_circuit(mul_instance, bp, assignmnt, k0_inp, start_row);
            typename mul_component::result_type k0_res = 
                components::generate_assignments(mul_instance, assignmnt, k0_inp, start_row);
            start_row = assignmnt.allocated_rows();

            typename mul_component::input_type k1_inp = {P_x, k0_res.output};
            components::generate_circuit(mul_instance, bp, assignmnt, k1_inp, start_row);
            typename mul_component::result_type k1_res = 
                components::generate_assignments(mul_instance, assignmnt, k1_inp, start_row);
            start_row = assignmnt.allocated_rows();

            typename mul_component::input_type k2_inp = {P_y, k0_res.output};
            components::generate_circuit(mul_instance, bp, assignmnt, k2_inp, start_row);
            typename mul_component::result_type k2_res = 
                components::generate_assignments(mul_instance, assignmnt, k2_inp, start_row);
            start_row = assignmnt.allocated_rows();


            typename add_component::input_type k3_inp = {P_x, k1_res.output};
            components::generate_circuit(add_instance, bp, assignmnt, k3_inp, start_row);
            typename add_component::result_type k3_res = 
                components::generate_assignments(add_instance, assignmnt, k3_inp, start_row);
            start_row = assignmnt.allocated_rows();

            typename sub_component::input_type k4_inp = {P_y, k2_res.output};
            components::generate_circuit(sub_instance, bp, assignmnt, k4_inp, start_row);
            typename sub_component::result_type k4_res = 
                components::generate_assignments(sub_instance, assignmnt, k4_inp, start_row);
            start_row = assignmnt.allocated_rows();

            // TODO3:
            // wee need copy constraint component for ed25519 base field elements

            for (std::size_t i = 0; i < 4; i++) {
                bp.add_copy_constraint({{k3_res.output[i].index, k3_res.output[i].rotation, false},
                                        {z0_res.output[i].index, z0_res.output[i].rotation, false}});
                
                bp.add_copy_constraint({{k4_res.output[i].index, k4_res.output[i].rotation, false},
                                        {z1_res.output[i].index, z1_res.output[i].rotation, false}});
            }

            frame.vectors[inst] = {P_x[0], P_x[1], P_x[2], P_x[3],
                                   P_y[0], P_y[1], P_y[2], P_y[3]};

        }
    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_CURVES_INTRINSIC_CURVE25519_ADDITION_HPP
