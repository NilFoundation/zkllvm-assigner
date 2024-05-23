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

#ifndef ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_HANDLE_COMPONENT_HPP_
#define ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_HANDLE_COMPONENT_HPP_

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/blueprint/utilities.hpp>

#include <nil/blueprint/component.hpp>
#include <nil/blueprint/basic_non_native_policy.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/addition.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/addition.hpp>
#include <nil/blueprint/components/algebra/curves/pasta/plonk/unified_addition.hpp>
#include <nil/blueprint/components/algebra/curves/edwards/plonk/non_native/complete_addition.hpp>
#include <nil/blueprint/components/algebra/curves/pasta/plonk/variable_base_scalar_mul.hpp>
#include <nil/blueprint/components/algebra/curves/edwards/plonk/non_native/variable_base_multiplication.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/division.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/division_or_zero.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/multiplication.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/multiplication.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/subtraction.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/subtraction.hpp>
#include <nil/blueprint/components/hashes/sha2/plonk/sha256.hpp>
#include <nil/blueprint/components/hashes/sha2/plonk/sha512.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/reduction.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/bit_decomposition.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/bit_composition.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/comparison_flag.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/bit_shift_constant.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/division_remainder.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/equality_flag.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/logic_ops.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/fri_array_swap.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/fri_cosets.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/fri_lin_inter.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/gate_argument_verifier.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/lookup_argument_verifier.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/permutation_argument_verifier.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/fri_cosets.hpp>

#include <nil/blueprint/component_mockups/is_in_g1.hpp>
#include <nil/blueprint/component_mockups/is_in_g2.hpp>
#include <nil/blueprint/component_mockups/h2c.hpp>
#include <nil/blueprint/component_mockups/fp12_multiplication.hpp>
#include <nil/blueprint/component_mockups/bls12_381_pairing.hpp>
#include <nil/blueprint/component_mockups/comparison.hpp>
#include <nil/blueprint/component_mockups/bitwise_and.hpp>
#include <nil/blueprint/component_mockups/bitwise_or.hpp>
#include <nil/blueprint/component_mockups/bitwise_xor.hpp>

#include <nil/blueprint/asserts.hpp>
#include <nil/blueprint/stack.hpp>
#include <nil/blueprint/statistics.hpp>
#include <nil/blueprint/policy/policy_manager.hpp>

#include <nil/blueprint/table_piece.hpp>

namespace nil {
    namespace blueprint {
        /**
         * @brief Assigner generation mode, defining which output types will be produced.
         *
         * A number of flags may be set:
         *
         * - CIRCUIT - generate circuit;
         * - ASSIGNMENTS - generate assignment table;
         * - SIZE_ESTIMATION - print circuit stats (generate nothing);
         * - PUBLIC_INPUT_COLUMN - generate public input column.
         *
         * Binary AND and OR can be applied to modes:
         * `mode_a | mode_b`, `mode_a & mode_b`.
         **/
        class generation_mode {
        private:
            enum modes : uint8_t {
                NONE = 0,
                CIRCUIT = 1 << 0,
                ASSIGNMENTS = 1 << 1,
                SIZE_ESTIMATION = 1 << 2,
                PUBLIC_INPUT_COLUMN = 1 << 3,
                FAST_TBL = 1 << 4,
            };

        public:
            constexpr generation_mode() : mode_(NONE) {
            }

            constexpr generation_mode(uint8_t mode) : mode_(mode) {
            }

            constexpr generation_mode(const generation_mode& other) : mode_(other.mode_) {
            }

            /// @brief "Do nothing" mode.
            constexpr static generation_mode none() {
                return generation_mode(NONE);
            }

            /// @brief Generate circuit.
            constexpr static generation_mode circuit() {
                return generation_mode(CIRCUIT);
            }

            /// @brief Generate assignment table.
            constexpr static generation_mode assignments() {
                return generation_mode(ASSIGNMENTS);
            }

            /// @brief Generate public input column.
            constexpr static generation_mode public_input_column() {
                return generation_mode(PUBLIC_INPUT_COLUMN);
            }

            /// @brief Print circuit statistics (generate nothing).
            constexpr static generation_mode size_estimation() {
                return generation_mode(SIZE_ESTIMATION);
            }

            /// @brief Generate table in a fast way.
            constexpr static generation_mode fast_tbl() {
                return generation_mode(FAST_TBL);
            }

            constexpr bool operator==(generation_mode other) const {
                return mode_ == other.mode_;
            }

            constexpr bool operator!=(generation_mode other) const {
                return mode_ != other.mode_;
            }

            constexpr generation_mode operator|(const generation_mode other) const {
                return generation_mode(mode_ | other.mode_);
            }

            constexpr generation_mode operator&(const generation_mode other) const {
                return generation_mode(mode_ & other.mode_);
            }

            generation_mode& operator=(const generation_mode& other) {
                mode_ = other.mode_;
                return *this;
            }

            generation_mode& operator|=(const generation_mode& other) {
                mode_ |= other.mode_;
                return *this;
            }

            generation_mode& operator&=(const generation_mode& other) {
                mode_ &= other.mode_;
                return *this;
            }

            /// @brief Whether generate circuit or not in this mode.
            constexpr bool has_circuit() const {
                return mode_ & CIRCUIT;
            }

            /// @brief Whether generate assignment table or not in this mode.
            constexpr bool has_assignments() const {
                return mode_ & ASSIGNMENTS;
            }

            /// @brief Whether print circuit statistics or not in this mode.
            constexpr bool has_size_estimation() const {
                return mode_ & SIZE_ESTIMATION;
            }

            /// @brief Whether generate public input column or not in this mode.
            constexpr bool has_public_input_column() const {
                return mode_ & PUBLIC_INPUT_COLUMN;
            }

            /// @brief Whether fast table generation or not in this mode.
            constexpr bool has_fast_tbl() const {
                return mode_ & FAST_TBL;
            }

        private:
            uint8_t mode_;
        };

        template<typename var>
        const int column_to_uint(typename var::column_type type) {
            switch (type) {
                case var::witness: return 0;
                case var::public_input: return 1;
                case var::constant: return 2;
                case var::selector: return 3;
                default: UNREACHABLE("unknown column type");
            }
        }

        template<typename var>
        struct component_io {
            std::size_t start_row;
            std::vector<var> inputs;
            std::vector<var> outputs;

            component_io (std::size_t s, std::vector<var> i, std::vector<var> o) {
                start_row = s;
                inputs = i;
                outputs = o;
            }
        };

        std::vector<
            component_io<
                crypto3::zk::snark::plonk_variable<
                    typename crypto3::algebra::curves::pallas::base_field_type::value_type
                >
            >
        > all_components = {};

        struct common_component_parameters {
            std::uint32_t curr_prover_idx;
            std::uint32_t target_prover_idx;
            generation_mode gen_mode;
        };

        template<typename BlueprintFieldType, typename ComponentType>
        void handle_component_input(
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                &assignment,
            typename ComponentType::input_type& instance_input, const common_component_parameters& param) {

            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

            std::vector<std::reference_wrapper<var>> input = instance_input.all_vars();
            const auto& used_rows = assignment.get_used_rows();

            for (auto& v : input) {
                BOOST_LOG_TRIVIAL(trace) << "input var:  " << v.get() << " " << var_value(assignment, v.get()).data;

                // component input can't be from internal_storage'
                ASSERT(!detail::is_internal<var>(v.get()) && detail::is_initialized<var>(v.get()));
                if ((used_rows.find(v.get().rotation) == used_rows.end()) &&
                           (v.get().type == var::column_type::witness || v.get().type == var::column_type::constant)) {
                    var new_v;
                    if (param.gen_mode.has_assignments()) {
                        new_v = save_shared_var(assignment, v);
                    } else {
                        const auto& shared_idx = assignment.shared_column_size(0);
                        assignment.shared(0, shared_idx) = BlueprintFieldType::value_type::zero();
                        new_v = var(1, shared_idx, false, var::column_type::public_input);
                        nil::blueprint::to_be_shared.emplace_back(assignment.get_id(), v.get());
                    }
                    v.get().index = new_v.index;
                    v.get().rotation = new_v.rotation;
                    v.get().relative = new_v.relative;
                    v.get().type = new_v.type;
                }
            }
        }

        template<typename BlueprintFieldType, typename ComponentType>
        void generate_circuit(
            ComponentType& component_instance,
            circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                &assignment,
            const typename ComponentType::input_type& instance_input,
            std::uint32_t start_row) {

            if constexpr( use_lookups<ComponentType>() ){
                auto lookup_tables = component_instance.component_lookup_tables();
                for(auto &[k,v]:lookup_tables){
                    bp.reserve_table(k);
                }
            };

            components::generate_circuit(component_instance, bp, assignment, instance_input, start_row);
        }

        template<typename T> struct has_get_empty_rows_amount{
        private:
            static int detect(...);
            template<typename U> static decltype(std::declval<U>().get_empty_rows_amount()) detect(const U&);
        public:
            static constexpr bool value = std::is_same<std::size_t, decltype(detect(std::declval<T>()))>::value;
        };

        template<bool>
        struct generate_empty_assignments_if_exist {
            template<typename BlueprintFieldType, typename ComponentType>
            static typename ComponentType::result_type implementation(const ComponentType& component_instance,
                      assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                          &assignment,
                      const typename ComponentType::input_type& instance_input, std::uint32_t start_row) {
                return components::generate_assignments(component_instance, assignment, instance_input, start_row);
            }
        };

        template<>
        struct generate_empty_assignments_if_exist<true> {
            template<typename BlueprintFieldType, typename ComponentType>
            static typename ComponentType::result_type implementation(const ComponentType& component_instance,
                                                                      assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                                                                          &assignment,
                                                                      const typename ComponentType::input_type& instance_input, std::uint32_t start_row) {
                return components::generate_empty_assignments(component_instance, assignment, instance_input, start_row);
            }
        };

        template<typename BlueprintFieldType, typename ComponentType>
        typename ComponentType::result_type generate_assignments(
            const ComponentType& component_instance,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                &assignment,
            const typename ComponentType::input_type& instance_input,
            std::uint32_t start_row, std::uint32_t target_prover_idx) {

            if (target_prover_idx == assignment.get_id() || target_prover_idx == std::numeric_limits<std::uint32_t>::max()) {
                return components::generate_assignments(component_instance, assignment, instance_input,
                                                        start_row);
            } else {
                return generate_empty_assignments_if_exist<has_get_empty_rows_amount<ComponentType>::value>::
                    implementation(component_instance, assignment, instance_input, start_row);
            }
        }

        template<typename BlueprintFieldType, typename ComponentType, typename... Args>
        typename ComponentType::result_type get_component_result(
                circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                &assignment,
                column_type<BlueprintFieldType> &internal_storage,
                component_calls &statistics,
                const common_component_parameters& param,
                typename ComponentType::input_type& instance_input,
                Args... args) {

            const auto p = detail::PolicyManager::get_parameters(detail::ManifestReader<ComponentType>::get_witness(args...));

            ComponentType component_instance(
                p.witness,
                std::array<std::uint32_t, 1>{0},
                std::array<std::uint32_t, 1>{0},
                args...);

            BOOST_LOG_TRIVIAL(debug) << "Using component \"" << component_instance.component_name << "\"";

            if (param.gen_mode.has_size_estimation()) {
                statistics.add_record(
                    component_instance.component_name,
                    component_instance.rows_amount,
                    component_instance.gates_amount,
                    component_instance.witness_amount()
                );
                return typename ComponentType::result_type(component_instance, assignment.allocated_rows());
            }

            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
            // BOOST_LOG_TRIVIAL(info) << "component " << component_instance.component_name;
            std::vector<var> inputs = {};
            for (std::size_t i = 0; i < instance_input.all_vars().size(); i++) {
                inputs.push_back(instance_input.all_vars()[i].get());
                // BOOST_LOG_TRIVIAL(info) << "input var " << instance_input.all_vars()[i].get().index << " " << instance_input.all_vars()[i].get().rotation << " " <<  column_to_uint<var>(instance_input.all_vars()[i].get().type);
            }

            handle_component_input<BlueprintFieldType, ComponentType>(assignment, instance_input, param);

            const auto& start_row = assignment.allocated_rows();
            // copy constraints before execute component
            const auto num_copy_constraints = bp.copy_constraints().size();

            // generate circuit in any case for fill selectors
            generate_circuit(component_instance, bp, assignment, instance_input, start_row);

            auto res = typename ComponentType::result_type(component_instance, start_row);
            std::vector<var> outputs = {};
            for (std::size_t i = 0; i < res.all_vars().size(); i++) {
                var curr_outp = res.all_vars()[i].get();
                outputs.push_back(curr_outp);
                comp_counter_form_var[curr_outp] = table_pieces.size();
                    // BOOST_LOG_TRIVIAL(info) << "res.all_vars() " << res.all_vars()[i].get().index << " " << res.all_vars()[i].get().rotation << " " << column_to_uint<var>(res.all_vars()[i].get().type);
            }

            std::vector<std::size_t> parents = {};
            for (std::size_t i = 0; i < inputs.size(); i++) {
                auto it = comp_counter_form_var.find(inputs[i]);
                if (comp_counter_form_var.find(inputs[i]) == comp_counter_form_var.end()) {
                    continue;
                }
                parents.push_back(comp_counter_form_var[inputs[i]]);
            }

            nil::blueprint::table_pieces.push_back(
                table_piece<var>(
                    table_pieces.size(),
                    parents,
                    component_instance.component_name,
                    start_row,
                    inputs,
                    outputs,
                    param.curr_prover_idx
                )
            );

            if (param.gen_mode.has_assignments()) {
                return generate_assignments(component_instance, assignment, instance_input, start_row,
                                            param.target_prover_idx);
            } else {
                const auto rows_amount = ComponentType::get_rows_amount(p.witness.size(), args...);
                // fake allocate rows
                for (std::uint32_t i = 0; i < rows_amount; i++) {
                    assignment.witness(0, start_row + i) = BlueprintFieldType::value_type::zero();
                }
                return typename ComponentType::result_type(component_instance, start_row);
            }
        }

        template<typename BlueprintFieldType, typename ComponentType>
        void handle_component_result(
                assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                &assignment,
                const llvm::Instruction *inst,
                stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
                typename ComponentType::result_type& component_result, generation_mode gen_mode) {

            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

            std::vector<std::reference_wrapper<var>> output = component_result.all_vars();


            if (output.size() == 1) {
                frame.scalars[inst] = output[0].get();
            } else {
                for (const auto &v : output) {
                    frame.vectors[inst].push_back(v.get());
                }
            }
            for (auto& v : output) {
                BOOST_LOG_TRIVIAL(trace) << "output var: " << v.get() << " " << var_value(assignment, v.get()).data;
            }

        }

        template<typename BlueprintFieldType>
        void handle_result(
                assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                &assignment,
                const llvm::Instruction *inst,
                stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
                const std::vector<typename crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>& result,
                generation_mode gen_mode) {

            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

            //touch result variables
            if (!gen_mode.has_assignments()) {
                for (const auto &v : result) {
                    if (v.type == var::column_type::witness) {
                        assignment.witness(v.index, v.rotation) = BlueprintFieldType::value_type::zero();
                    } else if (v.type == var::column_type::constant) {
                        assignment.constant(v.index, v.rotation) = BlueprintFieldType::value_type::zero();
                    }
                }
            }
            if (result.size() == 1) {
                frame.scalars[inst] = result[0];
            } else {
                frame.vectors[inst] = result;
            }
        }

        template<typename BlueprintFieldType, typename ComponentType, typename... Args>
        void handle_component(
                circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                &assignment,
                column_type<BlueprintFieldType> &internal_storage,
                component_calls &statistics,
                const common_component_parameters& param,
                typename ComponentType::input_type& instance_input,
                const llvm::Instruction *inst,
                stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
                Args... args) {

            auto component_result = get_component_result<BlueprintFieldType, ComponentType>
                    (bp, assignment, internal_storage, statistics, param, instance_input, args...);

            handle_component_result<BlueprintFieldType, ComponentType>(assignment, inst, frame, component_result, param.gen_mode);
        }

    }    // namespace blueprint
}    // namespace nil

#endif    // ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_HANDLE_COMPONENT_HPP_
