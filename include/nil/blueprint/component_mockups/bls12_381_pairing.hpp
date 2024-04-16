//---------------------------------------------------------------------------//
// Copyright (c) 2023 Alexey Yashunsky <a.yashunsky@nil.foundation>
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
// @file Declaration of the BLS12-381 pairing component
//---------------------------------------------------------------------------//

#ifndef ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_COMPONENT_MOCKUPS_BLS12_381_PAIRING_HPP_
#define ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_COMPONENT_MOCKUPS_BLS12_381_PAIRING_HPP_

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/crypto3/algebra/algorithms/pair.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {
                template<unsigned short int B, typename T>
                std::vector<unsigned short int> base(T x) {
                    std::vector<unsigned short int> res = {(unsigned short int)(x % B)};
                    if (x > 0) {
                        x /= B;
                        while (x > 0) {
                            res.insert(res.begin(), x % B);
                            x /= B;
                        }
                    }
                    return res;
                }
            }
            //
            // Component for computing the pairing of
            // two points: P from E(F_p) and Q from E'(F_p^2)
            // for BLS12-381.
            // Input: P[2], Q[4] ( we assume P and Q are NOT (0,0), i.e. not the points at infinity, NOT CHECKED )
            // Output: f[12]: an element of F_p^12
            //
            // It is just the Miller loop followed by exponentiation.
            // We realize the circuit in two versions - 12-column and 24-column.
            //

            using namespace detail;

            template<typename ArithmetizationType, typename BlueprintFieldType>
            class bls12_381_pairing;

            template<typename BlueprintFieldType>
            class bls12_381_pairing<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                           BlueprintFieldType>
                : public plonk_component<BlueprintFieldType> {

            static std::size_t gates_amount_internal(std::size_t witness_amount) {
                return
                    3 + // miller_loop
                    ((witness_amount == 12) ? 8 : 9); // bls12_exponentiation
            }

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::size_t witness_amount;

                    gate_manifest_type(std::size_t witness_amount_) : witness_amount(witness_amount_) {}

                    std::uint32_t gates_amount() const override {
                        return
                        3 + // miller_loop
                        ((witness_amount == 12) ? 8 : 9); // bls12_exponentiation
                    }

                    bool operator<(const component_gate_manifest *other) const override {
                        return (witness_amount < dynamic_cast<const gate_manifest_type*>(other)->witness_amount);
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount) {
                    static gate_manifest manifest =
                        gate_manifest(gate_manifest_type(witness_amount));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_range_param(12,24,12)), // 12 or 24
                        false
                    );

                    return manifest;
                }

                constexpr static std::size_t rows_amount_bls12_g2_point_addition(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return 1 + (witness_amount < 24);
                }


                static std::size_t rows_amount_miller_loop(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount, unsigned long long C_val) {
                    std::vector<unsigned short int> C_bin = base<2>(C_val);

                    return (C_bin.size()-1)*2 + // doubling LineFunctions
                                        (std::count(C_bin.begin(),C_bin.end(),1)-1)* // number of Adding blocks
                                        // LineFunction and point adder
                                        (4 + rows_amount_bls12_g2_point_addition(witness_amount, lookup_column_amount))
                                        + 2; // final result and extra point (for gate uniformity)
                }

                constexpr static std::size_t rows_amount_power_t(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return (witness_amount == 12)? 42 : 22; // 12 -> 42, 24 -> 22
                }


                constexpr static std::size_t rows_amount_power_tm1sq3_type(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return ((witness_amount == 12)? (59+3) : (32+2)) +  // 12 -> 59+3, 24 -> 32+2
                            rows_amount_power_t(witness_amount, lookup_column_amount);
                }

                constexpr static std::size_t rows_amount_bls12_exponentiation(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return ((witness_amount == 12)? (8 + 3 + 3 + 4 + 10) : (5 + 2 + 2 + 2 + 6)) +
                            rows_amount_power_tm1sq3_type(witness_amount,lookup_column_amount) +
                            3 * rows_amount_power_t(witness_amount, lookup_column_amount);
                }



                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount = 0) {
                    return rows_amount_miller_loop(witness_amount, lookup_column_amount,0xD201000000010000) +
                           rows_amount_bls12_exponentiation(witness_amount, lookup_column_amount);
                }

                const std::size_t gates_amount = gates_amount_internal(this->witness_amount());
                const std::size_t rows_amount = get_rows_amount(this->witness_amount());
                const std::string component_name = "native_bls12_381_pairing_unfinished";

                struct input_type {
                    std::array<var,2> P;
                    std::array<var,4> Q;

                    input_type(const std::vector<var>& input_vect) {
                        if (input_vect.size() != 6) {
                            throw std::out_of_range("Vector size does not match input size");
                        }
                        P[0] = input_vect[0];
                        P[1] = input_vect[1];
                        Q[0] = input_vect[2];
                        Q[1] = input_vect[3];
                        Q[2] = input_vect[4];
                        Q[3] = input_vect[5];
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result = {};
                        result.push_back(std::ref(P[0]));
                        result.push_back(std::ref(P[1]));
                        result.push_back(std::ref(Q[0]));
                        result.push_back(std::ref(Q[1]));
                        result.push_back(std::ref(Q[2]));
                        result.push_back(std::ref(Q[3]));
                        return result;
                    }
                };

                struct result_type {
        		    std::array<var,12> output;

                    result_type(const bls12_381_pairing &component, std::size_t start_row_index) {
                        std::size_t row = start_row_index;
                        output[0] = var(component.W(0), row++, false);
                        output[1] = var(component.W(0), row++, false);
                        output[2] = var(component.W(0), row++, false);
                        output[3] = var(component.W(0), row++, false);
                        output[4] = var(component.W(0), row++, false);
                        output[5] = var(component.W(0), row++, false);
                        output[6] = var(component.W(0), row++, false);
                        output[7] = var(component.W(0), row++, false);
                        output[8] = var(component.W(0), row++, false);
                        output[9] = var(component.W(0), row++, false);
                        output[10] = var(component.W(0), row++, false);
                        output[11] = var(component.W(0), row++, false);
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res;
                        std::copy(output.begin(), output.end(), std::back_inserter(res));
                        return res;
                    }
                };

                template<typename ContainerType>
                explicit bls12_381_pairing(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) { };

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                bls12_381_pairing(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) { };
                bls12_381_pairing(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) { };
            };

            template<typename BlueprintFieldType>
            using plonk_bls12_381_pairing =
                bls12_381_pairing<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                    BlueprintFieldType>;

            template<typename BlueprintFieldType>
            typename plonk_bls12_381_pairing<BlueprintFieldType>::result_type generate_assignments(
                const plonk_bls12_381_pairing<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_bls12_381_pairing<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = plonk_bls12_381_pairing<BlueprintFieldType>;
                using var = typename component_type::var;

                    std::uint32_t row = start_row_index;


                    typename crypto3::algebra::curves::bls12<381>::template g1_type<>::value_type g1 = {
                        var_value(assignment, instance_input.P[0]),
                        var_value(assignment, instance_input.P[1]),
                                // var_value(assignments[currProverIdx], frame.vectors[inst->getOperand(0)][0]),
                                // var_value(assignments[currProverIdx], frame.vectors[inst->getOperand(0)][1]),
                                crypto3::algebra::curves::bls12<381>::template g1_type<>::field_type::value_type::one()
                            };

                    typename crypto3::algebra::curves::bls12<381>::template g2_type<>::value_type g2 = {
                        typename crypto3::algebra::curves::bls12<381>::template g2_type<>::field_type::value_type(
                                    var_value(assignment, instance_input.Q[0]),
                                    var_value(assignment, instance_input.Q[1])
                                ),
                                typename crypto3::algebra::curves::bls12<381>::template g2_type<>::field_type::value_type(
                                    var_value(assignment, instance_input.Q[2]),
                                    var_value(assignment, instance_input.Q[3])
                                ),
                                crypto3::algebra::curves::bls12<381>::template g2_type<>::field_type::value_type::one()
                            };

                            typename crypto3::algebra::curves::bls12<381>::gt_type::value_type gt =
                                crypto3::algebra::pair<crypto3::algebra::curves::bls12<381>>(g1, g2);

                            typename plonk_bls12_381_pairing<BlueprintFieldType>::result_type res(component, start_row_index);

                            assignment.witness(component.W(0), row) = gt.data[0].data[0].data[0];
                            res.output[0] = var(component.W(0), row++, false);
                            assignment.witness(component.W(0), row) = gt.data[0].data[0].data[1];
                            res.output[1] = var(component.W(0), row++, false);
                            assignment.witness(component.W(0), row) = gt.data[0].data[1].data[0];
                            res.output[2] = var(component.W(0), row++, false);
                            assignment.witness(component.W(0), row) = gt.data[0].data[1].data[1];
                            res.output[3] = var(component.W(0), row++, false);
                            assignment.witness(component.W(0), row) = gt.data[0].data[2].data[0];
                            res.output[4] = var(component.W(0), row++, false);
                            assignment.witness(component.W(0), row) = gt.data[0].data[2].data[1];
                            res.output[5] = var(component.W(0), row++, false);
                            assignment.witness(component.W(0), row) = gt.data[1].data[0].data[0];
                            res.output[6] = var(component.W(0), row++, false);
                            assignment.witness(component.W(0), row) = gt.data[1].data[0].data[1];
                            res.output[7] = var(component.W(0), row++, false);
                            assignment.witness(component.W(0), row) = gt.data[1].data[1].data[0];
                            res.output[8] = var(component.W(0), row++, false);
                            assignment.witness(component.W(0), row) = gt.data[1].data[1].data[1];
                            res.output[9] = var(component.W(0), row++, false);
                            assignment.witness(component.W(0), row) = gt.data[1].data[2].data[0];
                            res.output[10] = var(component.W(0), row++, false);
                            assignment.witness(component.W(0), row) = gt.data[1].data[2].data[1];
                            res.output[11] = var(component.W(0), row++, false);

                return res;
	    }

            template<typename BlueprintFieldType>
            std::vector<std::size_t> generate_gates(
                const plonk_bls12_381_pairing<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_bls12_381_pairing<BlueprintFieldType>::input_type
                    &instance_input) {
                return {};
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const plonk_bls12_381_pairing<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_bls12_381_pairing<BlueprintFieldType>::input_type &instance_input,
                const std::size_t start_row_index) {
            }

            template<typename BlueprintFieldType>
            typename plonk_bls12_381_pairing<BlueprintFieldType>::result_type generate_circuit(
                const plonk_bls12_381_pairing<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_bls12_381_pairing<BlueprintFieldType>::input_type &instance_input,
                const std::size_t start_row_index) {

                typename plonk_bls12_381_pairing<BlueprintFieldType>::result_type res(component, start_row_index);
                return res;
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_COMPONENT_MOCKUPS_BLS12_381_PAIRING_HPP_
