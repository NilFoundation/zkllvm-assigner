target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "assigner"

; Function Attrs: circuit mustprogress nounwind
define dso_local noundef __zkllvm_field_pallas_base @_Z24field_arithmetic_exampleu26__zkllvm_field_pallas_baseu26__zkllvm_field_pallas_base(__zkllvm_field_pallas_base noundef %a, __zkllvm_field_pallas_base noundef %b) local_unnamed_addr #0 {
entry:
  %add = add __zkllvm_field_pallas_base %a, %b
  %mul = mul __zkllvm_field_pallas_base %add, %a
  %mul1 = mul __zkllvm_field_pallas_base %mul, %mul
  %mul2 = mul __zkllvm_field_pallas_base %mul1, %mul
  %sub = sub __zkllvm_field_pallas_base %b, %a
  %div = sdiv __zkllvm_field_pallas_base %mul2, %sub
  %add3 = add __zkllvm_field_pallas_base %div, f0x12345678901234567890
  ret __zkllvm_field_pallas_base %add3
}

attributes #0 = { circuit mustprogress nounwind "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" }

!llvm.linker.options = !{}
!llvm.module.flags = !{!0, !1}
!llvm.ident = !{!2}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 7, !"frame-pointer", i32 2}
!2 = !{!"clang version 16.0.0 (git@github.com:NilFoundation/zkllvm-circifier.git 8d79290301f85623f70c3b4ee874ac5687ef78ed)"}
