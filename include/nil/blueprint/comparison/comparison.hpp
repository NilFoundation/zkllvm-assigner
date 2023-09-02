//---------------------------------------------------------------------------//
// Copyright (c) 2023 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ASSIGNER_COMPARISON_HPP
#define CRYPTO3_ASSIGNER_COMPARISON_HPP

#include "llvm/IR/Type.h"
#include "llvm/IR/TypeFinder.h"
#include "llvm/IR/TypedPointerType.h"

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/comparison_flag.hpp>

#include <nil/blueprint/asserts.hpp>
#include <nil/blueprint/stack.hpp>

namespace nil {
    namespace blueprint {

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        typename crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>
            handle_comparison_component(llvm::CmpInst::Predicate p,
                const typename crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type> &x,
                const typename crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type> &y,
                std::size_t Bitness,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                std::uint32_t start_row,
                std::size_t &public_input_idx) {

            using component_type = components::comparison_flag<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                3>;

            nil::blueprint::components::detail::comparison_mode Mode;

            switch (p) {
                case llvm::CmpInst::ICMP_EQ: {
                    bool res = (var_value(assignment, x) == var_value(assignment, y));
                    assignment.public_input(0, public_input_idx) = res;
                    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
                    return var(0, public_input_idx++, false, var::column_type::public_input);
                    break;
                }
                case llvm::CmpInst::ICMP_NE: {
                    bool res = (var_value(assignment, x) != var_value(assignment, y));
                    assignment.public_input(0, public_input_idx) = res;
                    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
                    return var(0, public_input_idx++, false, var::column_type::public_input);
                    break;
                }
                case llvm::CmpInst::ICMP_SGE:
                case llvm::CmpInst::ICMP_UGE:
                    Mode = nil::blueprint::components::detail::comparison_mode::GREATER_EQUAL;
                    break;
                case llvm::CmpInst::ICMP_SGT:
                case llvm::CmpInst::ICMP_UGT:
                    Mode = nil::blueprint::components::detail::comparison_mode::GREATER_THAN;
                    break;
                case llvm::CmpInst::ICMP_SLE:
                case llvm::CmpInst::ICMP_ULE:
                    Mode = nil::blueprint::components::detail::comparison_mode::LESS_EQUAL;
                    break;
                case llvm::CmpInst::ICMP_SLT:
                case llvm::CmpInst::ICMP_ULT:
                    Mode = nil::blueprint::components::detail::comparison_mode::LESS_THAN;
                    break;
                default:
                    BOOST_UNREACHABLE_MSG("Unsupported icmp predicate");
                    break;
            }

            std::size_t bitness = Bitness ? Bitness : BlueprintFieldType::value_bits - 1;

            component_type component_instance = component_type({0, 1, 2}, {0}, {0}, bitness, Mode);

            components::generate_circuit(component_instance, bp, assignment, {x, y}, start_row);
            return components::generate_assignments(component_instance, assignment, {x, y}, start_row).flag;
        }

    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_COMPARISON_HPP
