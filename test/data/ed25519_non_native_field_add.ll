; ModuleID = '/root/cblpok/zkllvm/zkllvm/examples/ed25519_field_examples/ed25519_field_add.cpp'
source_filename = "/root/cblpok/zkllvm/zkllvm/examples/ed25519_field_examples/ed25519_field_add.cpp"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

; Function Attrs: circuit mustprogress nounwind uwtable
define dso_local noundef __zkllvm_field_curve25519_base @_Z9field_addu30__zkllvm_field_curve25519_baseu30__zkllvm_field_curve25519_base(__zkllvm_field_curve25519_base noundef %a, __zkllvm_field_curve25519_base noundef %b) local_unnamed_addr #0 {
entry:
  %add = add __zkllvm_field_curve25519_base %a, %b
  ret __zkllvm_field_curve25519_base %add
}

attributes #0 = { circuit mustprogress nounwind uwtable "frame-pointer"="none" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }

!llvm.linker.options = !{}
!llvm.module.flags = !{!0, !1, !2, !3}
!llvm.ident = !{!4}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 8, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 2}
!4 = !{!"clang version 16.0.0 (git@github.com:NilFoundation/zkllvm-circifier.git 1af967026adc4c18933fa4e20db3324043912242)"}
