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

#ifndef CRYPTO3_BLUEPRINT_COMPONENT_INSTRUCTION_PARSER_HPP
#define CRYPTO3_BLUEPRINT_COMPONENT_INSTRUCTION_PARSER_HPP

#include <variant>
#include <stack>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/components/hashes/poseidon/plonk/poseidon_15_wires.hpp>
#include <nil/blueprint/components/hashes/sha256/plonk/sha256.hpp>

#include <llvm/IRReader/IRReader.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include "llvm/IR/Constants.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/TypeFinder.h"
#include "llvm/IR/TypedPointerType.h"
#include "llvm/IR/Intrinsics.h"

#include <nil/blueprint/gep_resolver.hpp>
#include <nil/blueprint/public_input.hpp>
#include <nil/blueprint/stack.hpp>
#include <nil/blueprint/fields/addition.hpp>
#include <nil/blueprint/fields/subtraction.hpp>
#include <nil/blueprint/fields/multiplication.hpp>
#include <nil/blueprint/fields/division.hpp>

#include <nil/blueprint/curves/addition.hpp>
#include <nil/blueprint/curves/subtraction.hpp>
#include <nil/blueprint/curves/multiplication.hpp>

namespace nil {
    namespace blueprint {

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        struct parser {

            using ArithmetizationType =
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
            using var = crypto3::zk::snark::plonk_variable<BlueprintFieldType>;

            circuit<ArithmetizationType> bp;
            assignment<ArithmetizationType> assignmnt;

        private:
            // TODO(maksenov): handle it properly and move to another file
            template <typename map_type>
            void handle_int_binop(const llvm::Instruction *inst, map_type &variables) {
                assert(inst->getOperand(0)->getType()->isIntegerTy());
                assert(inst->getOperand(1)->getType()->isIntegerTy());

                var x = variables[inst->getOperand(0)];
                var y = variables[inst->getOperand(1)];
                typename BlueprintFieldType::value_type res;
                switch (inst->getOpcode()) {
                    case llvm::Instruction::Add:
                        res = var_value(assignmnt, x) + var_value(assignmnt, y);
                        break;
                    case llvm::Instruction::Mul:
                        res = var_value(assignmnt, x) * var_value(assignmnt, y);
                        break;
                    default:
                        assert(1 == 0 && "Unsupported operation!");
                        break;
                }
                assignmnt.public_input(0, public_input_idx) = res;
                variables[inst] = var(0, public_input_idx++, false, var::column_type::public_input);
            }

            // TODO(maksenov): handle it properly and move to another file
            template<typename map_type>
            void handle_int_cmp(const llvm::ICmpInst *inst, map_type &variables) {
                var x = variables[inst->getOperand(0)];
                var y = variables[inst->getOperand(1)];
                bool res = false;
                switch (inst->getPredicate()) {
                    case llvm::CmpInst::ICMP_EQ:
                        res = var_value(assignmnt, x) == var_value(assignmnt, y);
                        break;
                    case llvm::CmpInst::ICMP_NE:
                        res = var_value(assignmnt, x) != var_value(assignmnt, y);
                        break;
                    case llvm::CmpInst::ICMP_SGE:
                    case llvm::CmpInst::ICMP_UGE:
                        res = var_value(assignmnt, x) >= var_value(assignmnt, y);
                        break;
                    case llvm::CmpInst::ICMP_SGT:
                    case llvm::CmpInst::ICMP_UGT:
                        res = var_value(assignmnt, x) > var_value(assignmnt, y);
                        break;
                    case llvm::CmpInst::ICMP_SLE:
                    case llvm::CmpInst::ICMP_ULE:
                        res = var_value(assignmnt, x) <= var_value(assignmnt, y);
                        break;
                    case llvm::CmpInst::ICMP_SLT:
                    case llvm::CmpInst::ICMP_ULT:
                        res = var_value(assignmnt, x) < var_value(assignmnt, y);
                        break;
                    default:
                        assert(false && "Unsupported predicate");
                        break;
                }
                assignmnt.public_input(0, public_input_idx) = res;
                variables[inst] = var(0, public_input_idx++, false, var::column_type::public_input);
            }

            void handle_ptr_cmp(const llvm::ICmpInst *inst, stack_frame<var> &frame) {
                Pointer<var> lhs = frame.pointers[inst->getOperand(0)];
                Pointer<var> rhs = frame.pointers[inst->getOperand(1)];
                bool res = false;
                switch (inst->getPredicate()) {
                    case llvm::CmpInst::ICMP_EQ:
                        res = lhs == rhs;
                        break;
                    case llvm::CmpInst::ICMP_NE:
                        res = !(lhs == rhs);
                        break;
                    default:
                        assert(false && "Unsupported predicate");
                        break;
                }
                assignmnt.public_input(0, public_input_idx) = res;
                frame.scalars[inst] = var(0, public_input_idx++, false, var::column_type::public_input);
            }

            typename BlueprintFieldType::value_type marshal_int_val(const llvm::Value *val) {
                assert(llvm::isa<llvm::ConstantField>(val) || llvm::isa<llvm::ConstantInt>(val));
                llvm::APInt int_val;
                if (llvm::isa<llvm::ConstantField>(val)) {
                    int_val = llvm::cast<llvm::ConstantField>(val)->getValue();
                } else {
                    int_val = llvm::cast<llvm::ConstantInt>(val)->getValue();
                }
                unsigned words = int_val.getNumWords();
                typename BlueprintFieldType::value_type field_constant;
                if (words == 1) {
                    field_constant = int_val.getZExtValue();
                } else {
                    // TODO(maksenov): avoid copying here
                    const char *APIntData = reinterpret_cast<const char *>(int_val.getRawData());
                    std::vector<char> bytes(APIntData, APIntData + words * 8);
                    nil::marshalling::status_type status;
                    field_constant = nil::marshalling::pack<nil::marshalling::option::little_endian>(bytes, status);
                    assert(status == nil::marshalling::status_type::success);
                }
                return field_constant;
            }

            Pointer<var> resolve_pointer(stack_frame<var> &frame, const llvm::Value *ptr_value) {
                if (llvm::isa<llvm::GlobalVariable>(ptr_value)) {
                    return globals[ptr_value];
                }
                assert(frame.pointers.find(ptr_value) != frame.pointers.end());
                return frame.pointers[ptr_value];
            }

            template<typename VarType>
            Chunk<VarType> store_constant(llvm::Constant *constant_init) {
                if (auto operation = llvm::dyn_cast<llvm::ConstantExpr>(constant_init)) {
                    assert(operation->isCast());
                    constant_init = operation->getOperand(0);
                }
                if (auto CS = llvm::cast<llvm::GlobalVariable>(constant_init)) {
                    assert(CS->isConstant());
                    constant_init = CS->getInitializer();
                }

                // We need to flatten a complex struct to put it into a chunk
                // So we use deep-first search for scalar elements of the struct (or array)
                Chunk<var> chunk;
                unsigned idx = 0;
                std::stack<llvm::Constant *> component_stack;
                component_stack.push(constant_init);
                while (!component_stack.empty()) {
                    llvm::Constant *constant = component_stack.top();
                    component_stack.pop();
                    llvm::Type *type = constant->getType();
                    if (!type->isAggregateType()) {
                        assignmnt.public_input(0, public_input_idx) = marshal_int_val(constant);
                        auto variable = var(0, public_input_idx++, false, var::column_type::public_input);
                        chunk.store_var(variable, idx++);
                        continue;
                    }
                    unsigned num_elements = 0;
                    if (llvm::isa<llvm::StructType>(type)) {
                        num_elements = type->getStructNumElements();
                    } else {
                        num_elements = type->getArrayNumElements();
                    }
                    // Start element must always be on the top of the stack,
                    // so put elements on top in reverse order
                    for (int i = num_elements - 1; i >= 0; --i) {
                        component_stack.push(constant->getAggregateElement(i));
                    }
                }
                return chunk;
            }

            bool handle_intrinsic(const llvm::CallInst *inst, llvm::Intrinsic::ID id, stack_frame<var> &frame, uint32_t start_row) {
                switch (id) {
                    case llvm::Intrinsic::assigner_malloc: {
                        global_data.emplace_back();
                        frame.pointers[inst] = Pointer<var>{&global_data.back(), 0};
                        return true;
                    }
                    case llvm::Intrinsic::assigner_free: {
                        Pointer<var> ptr = resolve_pointer(frame, inst->getOperand(0));
                        Chunk<var> *chunk = ptr.get_base();
                        auto entry = std::find_if(global_data.begin(), global_data.end(),
                                  [chunk](const Chunk<var> &elem) { return &elem == chunk; });
                        global_data.erase(entry);
                        return true;
                    }
                    case llvm::Intrinsic::assigner_poseidon: {
                        using component_type = components::poseidon<ArithmetizationType, BlueprintFieldType, 15>;

                        auto &input_block = frame.vectors[inst->getOperand(0)];
                        std::array<var, component_type::state_size> input_state_var;
                        std::copy(input_block.begin(), input_block.end(), input_state_var.begin());

                        typename component_type::input_type instance_input = {input_state_var};

                        component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, {},
                                                            {});

                        components::generate_circuit(component_instance, bp, assignmnt, instance_input, start_row);

                        typename component_type::result_type component_result =
                            components::generate_assignments(component_instance, assignmnt, instance_input, start_row);

                        std::vector<var> output(component_result.output_state.begin(),
                                                component_result.output_state.end());
                        frame.vectors[inst] = output;
                        return true;
                    }
                    case llvm::Intrinsic::assigner_sha2_256: {
                        using component_type = components::sha256<ArithmetizationType, 9>;

                        constexpr const std::int32_t block_size = 2;
                        constexpr const std::int32_t input_blocks_amount = 2;

                        auto &block_arg = frame.vectors[inst->getOperand(0)];
                        std::array<var, input_blocks_amount * block_size> input_block_vars;
                        std::copy(block_arg.begin(), block_arg.end(), input_block_vars.begin());

                        typename component_type::input_type instance_input = {input_block_vars};

                        component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8}, {0}, {});

                        components::generate_circuit(component_instance, bp, assignmnt, instance_input, start_row);

                        typename component_type::result_type component_result =
                            components::generate_assignments(component_instance, assignmnt, instance_input, start_row);

                        std::vector<var> output(component_result.output.begin(), component_result.output.end());
                        frame.vectors[inst] = output;
                        return true;
                    }
                    case llvm::Intrinsic::memcpy: {
                        Pointer<var> dst = resolve_pointer(frame, inst->getOperand(0));
                        llvm::Value *src_val = inst->getOperand(1);
                        if (auto constant = llvm::dyn_cast<llvm::Constant>(src_val)) {
                            auto chunk = store_constant<var>(constant);
                            dst.memcpy(&chunk);
                        } else {
                            Pointer<var> src = resolve_pointer(frame, src_val);
                            dst.memcpy(src);
                        }
                        return true;
                    }
                    case llvm::Intrinsic::assigner_zkml_convolution: {
                        assert(false && "zkml_convolution intrinsic is not implemented yet");
                        return false;
                    }
                    case llvm::Intrinsic::assigner_zkml_pooling: {
                        assert(false && "zkml_pooling intrinsic is not implemented yet");
                        return false;
                    }
                    case llvm::Intrinsic::assigner_zkml_ReLU: {
                        assert(false && "zkml_ReLU intrinsic is not implemented yet");
                        return false;
                    }
                    case llvm::Intrinsic::assigner_zkml_batch_norm: {
                        assert(false && "zkml_batch_norm intrinsic is not implemented yet");
                        return false;
                    }
                    case llvm::Intrinsic::lifetime_start:
                    case llvm::Intrinsic::lifetime_end:
                        // Nothing to do
                        return true;
                    default:
                        assert(false && "Unexpected intrinsic!");
                }
                return false;
            }

            const llvm::Instruction *handle_instruction(const llvm::Instruction *inst) {
                stack_frame<var> &frame = call_stack.top();
                auto &variables = frame.scalars;
                std::uint32_t start_row = assignmnt.allocated_rows();

                // Put constant operands to public input
                for (int i = 0; i < inst->getNumOperands(); ++i) {
                    llvm::Value *op = inst->getOperand(i);
                    if ((llvm::isa<llvm::ConstantField>(op) || llvm::isa<llvm::ConstantInt>(op)) &&
                        variables.find(op) == variables.end()) {
                        assignmnt.public_input(0, public_input_idx) = marshal_int_val(op);
                        variables[op] = var(0, public_input_idx++, false, var::column_type::public_input);
                    }
                }

                switch (inst->getOpcode()) {
                    case llvm::Instruction::Add: {

                        if (inst->getOperand(0)->getType()->isIntegerTy()) {
                            handle_int_binop(inst, variables);
                            return inst->getNextNonDebugInstruction();
                        }

                        if (inst->getOperand(0)->getType()->isFieldTy() && inst->getOperand(1)->getType()->isFieldTy()) {
                            handle_field_addition_component<BlueprintFieldType, ArithmetizationParams>(
                                        inst, frame, bp, assignmnt, start_row);
                            return inst->getNextNonDebugInstruction();
                        } else if (inst->getOperand(0)->getType()->isCurveTy() && inst->getOperand(1)->getType()->isCurveTy()) {
                            handle_curve_addition_component<BlueprintFieldType, ArithmetizationParams>(
                                        inst, frame, bp, assignmnt, start_row);
                            return inst->getNextNonDebugInstruction();
                        } else {
                            assert (1==0 && "curve + scalar is undefined");
                        }

                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Sub: {

                        if (inst->getOperand(0)->getType()->isFieldTy() && inst->getOperand(1)->getType()->isFieldTy()) {
                            handle_field_subtraction_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, frame, bp, assignmnt, start_row);
                            return inst->getNextNonDebugInstruction();
                        } else if (inst->getOperand(0)->getType()->isCurveTy() && inst->getOperand(1)->getType()->isCurveTy()) {
                            handle_curve_subtraction_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, frame, bp, assignmnt, start_row);
                            return inst->getNextNonDebugInstruction();
                        } else {
                            assert (1==0 && "curve - scalar is undefined");
                        }

                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Mul: {

                        if (inst->getOperand(0)->getType()->isIntegerTy()) {
                            handle_int_binop(inst, variables);
                            return inst->getNextNonDebugInstruction();
                        }

                        if (inst->getOperand(0)->getType()->isFieldTy() && inst->getOperand(1)->getType()->isFieldTy()) {
                            handle_field_multiplication_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, frame, bp, assignmnt, start_row);
                            return inst->getNextNonDebugInstruction();
                        } else {
                            assert(1==0 && "Mul opcode is defined only for fieldTy * fieldTy");
                        }

                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::CMul: {
                        if (
                            (inst->getOperand(0)->getType()->isCurveTy() && inst->getOperand(1)->getType()->isFieldTy()) ||
                            (inst->getOperand(1)->getType()->isCurveTy() && inst->getOperand(0)->getType()->isFieldTy())) {

                            handle_curve_multiplication_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, frame, bp, assignmnt, start_row);
                            return inst->getNextNonDebugInstruction();
                        } else {
                            assert (1==0 && "cmul opcode is defined only for curveTy * fieldTy");
                        }
                    }
                    case llvm::Instruction::UDiv:
                    case llvm::Instruction::SDiv: {

                        handle_field_division_component<BlueprintFieldType, ArithmetizationParams>(
                            inst, frame, bp, assignmnt, start_row);

                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Call: {
                        auto *call_inst = llvm::cast<llvm::CallInst>(inst);
                        auto *fun = call_inst->getCalledFunction();
                        if (fun == nullptr) {
                            std::cerr << "Unresolved call";
                            return nullptr;
                        }
                        llvm::StringRef fun_name = fun->getName();
                        assert(fun->arg_size() == call_inst->getNumOperands() - 1);
                        if (fun->isIntrinsic()) {
                            if (!handle_intrinsic(call_inst, fun->getIntrinsicID(), frame, start_row))
                                return nullptr;
                            return inst->getNextNonDebugInstruction();
                        }
                        if (fun->empty()) {
                            std::cerr << "Function " << fun_name.str() << " has no implementation." << std::endl;
                            return inst->getNextNonDebugInstruction();
                        }
                        stack_frame<var> new_frame;
                        auto &new_variables = new_frame.scalars;
                        for (int i = 0; i < fun->arg_size(); ++i) {
                            llvm::Argument *arg = fun->getArg(i);
                            if (arg->getType()->isPointerTy())
                                new_frame.pointers[arg] = frame.pointers[call_inst->getOperand(i)];
                            else if (arg->getType()->isVectorTy())
                                new_frame.vectors[arg] = frame.vectors[call_inst->getOperand(i)];
                            else
                                new_variables[arg] = variables[call_inst->getOperand(i)];

                        }
                        new_frame.caller = call_inst;
                        call_stack.emplace(std::move(new_frame));
                        return &fun->begin()->front();
                    }
                    case llvm::Instruction::ICmp: {
                        auto cmp_inst = llvm::cast<const llvm::ICmpInst>(inst);
                        if (cmp_inst->getOperand(0)->getType()->isIntegerTy()
                            || cmp_inst->getOperand(0)->getType()->isFieldTy())
                            handle_int_cmp(cmp_inst, variables);
                        else if (cmp_inst->getOperand(0)->getType()->isPointerTy())
                            handle_ptr_cmp(cmp_inst, frame);
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Select: {

                        var condition = variables[inst->getOperand(0)];
                        llvm::Value *true_val = inst->getOperand(1);
                        llvm::Value *false_val = inst->getOperand(2);
                        if (var_value(assignmnt, condition) != 0) {
                            variables[inst] = variables[true_val];
                        } else {
                            variables[inst] = variables[false_val];
                        }
                        return inst->getNextNonDebugInstruction();
                    }

                    case llvm::Instruction::Br: {
                        // Save current basic block to resolve PHI inst further
                        predecessor = inst->getParent();

                        if (inst->getNumOperands() != 1) {
                            assert(inst->getNumOperands() == 3);
                            auto false_bb = llvm::cast<llvm::BasicBlock>(inst->getOperand(1));
                            auto true_bb = llvm::cast<llvm::BasicBlock>(inst->getOperand(2));
                            var cond = variables[inst->getOperand(0)];
                            if (var_value(assignmnt, cond) != 0)
                                return &true_bb->front();
                            return &false_bb->front();
                        }
                        auto bb_to_jump = llvm::cast<llvm::BasicBlock>(inst->getOperand(0));
                        return &bb_to_jump->front();
                    }
                    case llvm::Instruction::PHI: {
                        auto phi_node = llvm::cast<llvm::PHINode>(inst);
                        for (int i = 0; i < phi_node->getNumIncomingValues(); ++i) {
                            if (phi_node->getIncomingBlock(i) == predecessor) {
                                llvm::Value *incoming_value = phi_node->getIncomingValue(i);
                                llvm::Type *value_type = incoming_value->getType();
                                if (value_type->isPointerTy()) {
                                    assert(frame.pointers.find(incoming_value) != frame.pointers.end());
                                    frame.pointers[phi_node] = frame.pointers[incoming_value];
                                } else if (value_type->isIntegerTy() ||
                                           (value_type->isFieldTy() && field_arg_num<BlueprintFieldType>(value_type) == 1)) {
                                    assert(variables.find(incoming_value) != variables.end());
                                    variables[phi_node] = variables[incoming_value];
                                } else {
                                    assert(frame.vectors.find(incoming_value) != frame.vectors.end());
                                    frame.vectors[phi_node] = frame.vectors[incoming_value];
                                }
                                return phi_node->getNextNonDebugInstruction();
                            }
                        }
                        assert(false && "Incoming value for phi was not found");
                        break;
                    }
                    case llvm::Instruction::InsertElement: {
                        auto insert_inst = llvm::cast<llvm::InsertElementInst>(inst);
                        llvm::Value *vec = insert_inst->getOperand(0);
                        llvm::Value *index_value = insert_inst->getOperand(2);
                        if (!llvm::isa<llvm::ConstantInt>(index_value)) {
                            std::cerr << "Only constant indices for a vector are supported" << std::endl;
                            return nullptr;
                        }

                        int index = llvm::cast<llvm::ConstantInt>(index_value)->getZExtValue();
                        std::vector<var> result_vector;
                        if (llvm::isa<llvm::Constant>(vec)) {
                            auto *vector_type = llvm::cast<llvm::FixedVectorType>(vec->getType());
                            assert(vector_type->getElementType()->isFieldTy());
                            unsigned size = vector_type->getNumElements();
                            result_vector = std::vector<var>(size);
                            if (auto *cv = llvm::dyn_cast<llvm::ConstantVector>(vec)) {
                                for (int i = 0; i < size; ++i) {
                                    llvm::Constant *elem = cv->getAggregateElement(i);
                                    if (llvm::isa<llvm::UndefValue>(elem))
                                        continue;
                                    assignmnt.public_input(0, public_input_idx) = marshal_int_val(elem);
                                    result_vector[i] = var(0, public_input_idx++, false, var::column_type::public_input);
                                }
                            } else {
                                assert(llvm::isa<llvm::UndefValue>(vec) && "Unexpected constant value!");
                            }
                        } else {
                            result_vector = frame.vectors[vec];
                        }
                        result_vector[index] = variables[inst->getOperand(1)];
                        frame.vectors[inst] = result_vector;
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::ExtractElement: {
                        auto extract_inst = llvm::cast<llvm::ExtractElementInst>(inst);
                        llvm::Value *vec = extract_inst->getOperand(0);
                        llvm::Value *index_value = extract_inst->getOperand(1);
                        if (!llvm::isa<llvm::ConstantInt>(index_value)) {
                            std::cerr << "Only constant indices for a vector are supported" << std::endl;
                            return nullptr;
                        }
                        int index = llvm::cast<llvm::ConstantInt>(index_value)->getZExtValue();
                        variables[inst] = frame.vectors[vec][index];
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Alloca:
                        frame.memory.emplace_back();
                        call_stack.top().pointers[inst] = Pointer<var>{&frame.memory.back(), 0};
                        return inst->getNextNonDebugInstruction();
                    case llvm::Instruction::GetElementPtr: {
                        auto *gep = llvm::cast<llvm::GetElementPtrInst>(inst);
                        llvm::Value *idx1 = gep->getOperand(1);
                        if (!llvm::isa<llvm::ConstantInt>(idx1) || !llvm::cast<llvm::ConstantInt>(idx1)->isZero()) {
                            std::cerr << "Unsupported gep inst" << std::endl;
                            return nullptr;
                        }
                        llvm::Value *idx2 = gep->getOperand(2);
                        var x = variables[idx2];
                        auto v = var_value(assignmnt, x);
                        int gep_index = (int)static_cast<typename BlueprintFieldType::integral_type>(v.data);
                        int resolved_index = gep_resolver.get_flat_index(gep->getSourceElementType(), gep_index);
                        Pointer<var> ptr = frame.pointers[gep->getPointerOperand()].adjust(resolved_index);
                        frame.pointers[gep] = ptr;
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Load: {
                        auto *load_inst = llvm::cast<llvm::LoadInst>(inst);
                        Pointer<var> ptr = resolve_pointer(frame, load_inst->getPointerOperand());
                        llvm::Type *load_type = load_inst->getType();
                        if (load_type->isPointerTy()) {
                            frame.pointers[load_inst] = ptr.load_pointer();
                        } else if (load_type->isIntegerTy() ||
                                   (load_type->isFieldTy() && field_arg_num<BlueprintFieldType>(load_type) == 1)) {
                            variables[load_inst] = ptr.load_var();
                        } else {
                            frame.vectors[load_inst] = ptr.load_vector();
                        }
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Store: {
                        auto *store_inst = llvm::cast<llvm::StoreInst>(inst);
                        Pointer<var> ptr = resolve_pointer(frame, store_inst->getPointerOperand());
                        const llvm::Value *val = store_inst->getValueOperand();
                        llvm::Type *store_type = val->getType();
                        if (store_type->isPointerTy()) {
                            ptr.store_pointer(frame.pointers[val]);
                        } else if (store_type->isIntegerTy() ||
                                   (store_type->isFieldTy() && field_arg_num<BlueprintFieldType>(store_type) == 1)) {
                            ptr.store_var(variables[val]);
                        } else {
                            ptr.store_vector(frame.vectors[val]);
                        }
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::BitCast: {
                        // just return pointer argument as is
                        frame.pointers[inst] = resolve_pointer(frame, inst->getOperand(0));
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Ret: {
                        auto extracted_frame = std::move(call_stack.top());
                        call_stack.pop();
                        if (extracted_frame.caller == nullptr) {
                            // Final return
                            assert(call_stack.size() == 0);
                            finished = true;
                            return nullptr;
                        }
                        if (inst->getNumOperands() != 0) {
                            llvm::Value *ret_val = inst->getOperand(0);
                            if (ret_val->getType()->isPointerTy()) {
                                auto &upper_frame_pointers = call_stack.top().pointers;
                                auto res = extracted_frame.pointers[ret_val];
                                upper_frame_pointers[extracted_frame.caller] = res;
                            } else if (ret_val->getType()->isVectorTy()) {
                                auto &upper_frame_vectors = call_stack.top().vectors;
                                auto res = extracted_frame.vectors[ret_val];
                                upper_frame_vectors[extracted_frame.caller] = res;
                            } else {
                                auto &upper_frame_variables = call_stack.top().scalars;
                                upper_frame_variables[extracted_frame.caller] = extracted_frame.scalars[ret_val];
                            }
                        }
                        return extracted_frame.caller->getNextNonDebugInstruction();
                    }

                    default:
                        std::cerr << inst->getOpcodeName() << std::endl;
                        assert(1 == 0 && "unsupported opcode type");
                }
                return nullptr;
            }

        public:
            std::unique_ptr<llvm::Module> parseIRFile(const char *ir_file) {
                llvm::SMDiagnostic diagnostic;
                std::unique_ptr<llvm::Module> module = llvm::parseIRFile(ir_file, diagnostic, context);
                if (module == nullptr) {
                    std::cout << "Unable to parse IR file: " + diagnostic.getMessage().str() << std::endl;
                }
                return module;
            }

            template<typename PublicInputContainerType>
            bool evaluate(const llvm::Module &module, const PublicInputContainerType &public_input) {

                stack_frame<var> base_frame;
                auto &variables = base_frame.scalars;
                auto &pointers = base_frame.pointers;
                base_frame.caller = nullptr;
                auto entry_point_it = module.end();
                for (auto function_it = module.begin(); function_it != module.end(); ++function_it) {
                    if (function_it->hasFnAttribute(llvm::Attribute::Circuit)) {
                        if (entry_point_it != module.end()) {
                            std::cerr << "More then one functions with [[circuit]] attribute in the module"
                                      << std::endl;
                            return false;
                        }
                        entry_point_it = function_it;
                    }
                }
                if (entry_point_it == module.end()) {
                    std::cerr << "Entry point is not found" << std::endl;
                    return false;
                }
                auto &function = *entry_point_it;

                auto public_input_reader =
                    PublicInputReader<BlueprintFieldType, var, assignment<ArithmetizationType>,
                                      PublicInputContainerType>(base_frame, assignmnt, public_input);
                if (!public_input_reader.fill_public_input(function)) {
                    std::cerr << "Public input must match the size of arguments" << std::endl;
                    return false;
                }
                public_input_idx = public_input.size();
                call_stack.emplace(std::move(base_frame));

                for (const llvm::GlobalVariable &global : module.getGlobalList()) {
                    global_data.emplace_back();
                    auto ptr = Pointer<var>(&global_data.back(), 0);
                    globals[&global] = ptr;
                    if (!global.getInitializer()->getType()->isIntegerTy() &&
                        !global.getInitializer()->getType()->isFieldTy()) {
                        // Only int and field constants are supported for now
                        continue;
                    }
                    assignmnt.public_input(0, public_input_idx) = marshal_int_val(global.getInitializer());
                    ptr.store_var(var(0, public_input_idx++, false, var::column_type::public_input));
                }
                const llvm::Instruction *next_inst = &function.begin()->front();
                while (true) {
                    next_inst = handle_instruction(next_inst);
                    if (finished) {
                        return true;
                    }
                    if (next_inst == nullptr) {
                        return false;
                    }
                }
            }

        private:
            llvm::LLVMContext context;
            const llvm::BasicBlock *predecessor = nullptr;
            std::stack<stack_frame<var>> call_stack;
            std::map<const llvm::Value *, Pointer<var>> globals;
            std::list<Chunk<var>> global_data;
            bool finished = false;
            size_t public_input_idx = 0;
            GepResolver gep_resolver;
        };

    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENT_INSTRUCTION_PARSER_HPP
