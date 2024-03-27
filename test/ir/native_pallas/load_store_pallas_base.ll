target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-v768:8-v1152:8-v1536:8-i64:64-f80:128-n8:16:32:64-S128"
target triple = "assigner"

define __zkllvm_field_pallas_base @main() #1 {
entry:
    %ptr = alloca __zkllvm_field_pallas_base
    store __zkllvm_field_pallas_base f0x9, ptr %ptr
    %val = load __zkllvm_field_pallas_base, ptr %ptr
    ret __zkllvm_field_pallas_base %val
}

attributes #1 = { circuit }
