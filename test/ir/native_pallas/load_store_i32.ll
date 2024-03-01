target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-v768:8-v1152:8-v1536:8-i64:64-f80:128-n8:16:32:64-S128"
target triple = "assigner"

define i32 @main() #1 {
entry:
    %ptr = alloca i32
    store i32 9, ptr %ptr
    %val = load i32, ptr %ptr
    ret i32 %val
}

attributes #1 = { circuit }
