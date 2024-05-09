//---------------------------------------------------------------------------//
// Copyright (c) 2023 Alexey Kokoshnikov <alexeikokoshnikov@nil.foundation>
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

#ifndef ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_UTILITIES_HPP_
#define ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_UTILITIES_HPP_

#include <vector>
#include <array>
#include <limits>

#include <nil/blueprint/asserts.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/blueprint/plonk/assignment_proxy.hpp>

namespace nil {
    namespace blueprint {

        template<typename T>
        using column_type = typename crypto3::zk::snark::plonk_column<T>;

        namespace detail {

            struct FlexibleParameters {
                std::vector <std::uint32_t> witness;

                FlexibleParameters(std::uint32_t witness_amount) {
                    witness.resize(witness_amount);
                    std::iota(witness.begin(), witness.end(), 0); // fill 0, 1, ...
                }
            };

            struct CompilerRestrictions {
                inline static compiler_manifest common_restriction_manifest = compiler_manifest(15, // TODO hardcoded
                                                                                                true);
            };

            template<typename ComponentType>
            struct ManifestReader {

                template<typename... Args>
                static std::vector <std::pair<std::uint32_t, std::uint32_t>>
                get_witness(Args... args) {
                    typename ComponentType::manifest_type manifest =
                        CompilerRestrictions::common_restriction_manifest.intersect(ComponentType::get_manifest(args...));
                    ASSERT(manifest.is_satisfiable());
                    auto witness_amount_ptr = manifest.witness_amount;
                    std::vector <std::pair<std::uint32_t, std::uint32_t>> values;
                    for (auto it = witness_amount_ptr->begin();
                         it != witness_amount_ptr->end(); it++) {
                        const auto witness_amount = *it;
                        const auto rows_amount = ComponentType::get_rows_amount(witness_amount,
                                                                                args...);
                        const auto total_amount_rows_power_two = std::pow(2, std::ceil(std::log2(rows_amount)));
                        const auto total_amount_of_gates = ComponentType::get_gate_manifest(witness_amount, args...).get_gates_amount();
                        values.emplace_back(witness_amount,
                                            total_amount_rows_power_two + total_amount_of_gates);
                    }
                    ASSERT(values.size() > 0);
                    return values;
                }

                static typename ComponentType::component_type::constant_container_type
                get_constants() {
                    typename ComponentType::component_type::constant_container_type constants;
                    std::iota(constants.begin(), constants.end(), 0); // fill 0, 1, ...
                    return constants;
                }

                static typename ComponentType::component_type::public_input_container_type
                get_public_inputs() {
                    typename ComponentType::component_type::public_input_container_type public_inputs;
                    std::iota(public_inputs.begin(), public_inputs.end(), 0); // fill 0, 1, ...
                    return public_inputs;
                }
            };

            template<typename InputType, typename BlueprintFieldType, typename var>
            var put_shared(InputType input,
                assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment) {
                const auto& shared_idx = assignment.shared_column_size(0);
                assignment.shared(0, shared_idx) = input;
                return var(1, shared_idx, false, var::column_type::public_input);
            }

            // TODO: column index is hardcoded but shouldn't be in the future
            template<typename InputType, typename BlueprintFieldType, typename var>
            var put_constant(InputType input,
                           assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment) {
                const auto& constant_idx = assignment.constant(1).size();
                assignment.constant(1, constant_idx) = input;
                return var(1, constant_idx, false, var::column_type::constant);
            }

            static constexpr const std::size_t internal_storage_index = std::numeric_limits<std::size_t>::max();

            template<typename InputType, typename BlueprintFieldType, typename var>
            var put_internal_value(InputType input,
                           column_type<BlueprintFieldType> &storage) {
                const auto idx = storage.size();
                storage.push_back(input);
                return var(internal_storage_index, idx, false, var::column_type::constant);
            }

            template<typename BlueprintFieldType, typename var>
            typename BlueprintFieldType::value_type var_value(const var &input_var,
                           const assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                           column_type<BlueprintFieldType> &storage, bool has_assignments) {
                if (input_var.type == var::column_type::constant && input_var.index == detail::internal_storage_index) {
                    ASSERT(input_var.rotation < storage.size());
                    return storage[input_var.rotation];
                }
                if (input_var.type == var::column_type::constant || has_assignments) {
                    return var_value(assignment, input_var);
                }
                return 0;
            }

            template<typename var>
            bool is_internal(const var &v) {
                if (v.type == var::column_type::constant && v.index == detail::internal_storage_index) {
                    return true;
                }
                return false;
            }

            template<typename var>
            bool is_initialized(const var &v) {
                return (v.type != var::column_type::uninitialized);
            }
        }    // namespace detail
    }    // namespace blueprint
}    // namespace nil

#endif    // ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_UTILITIES_HPP_
