; ModuleID = 'llvm-link'
source_filename = "llvm-link"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-v768:8-v1152:8-v1536:8-i64:64-f80:128-n8:16:32:64-S128"
target triple = "assigner"

%"struct.array2" = type { [2 x __zkllvm_field_pallas_base] }
%"struct.array3" = type { [3 x __zkllvm_field_pallas_base] }
%"struct.array5" = type { [5 x __zkllvm_field_pallas_base] }


define void @arrays(ptr sret(%"struct.array2") align 1 %agg.result, ptr byval(%"struct.array3") %vertexes, ptr noundef byval(%"struct.array5") %weights) {
entry:
  ret void
}

define void @fields_curves(__zkllvm_field_pallas_base %pallas, __zkllvm_field_curve25519_base %ed25519, __zkllvm_curve_pallas %pallasc, __zkllvm_curve_curve25519 %edc) {
entry:
  ret void
}
