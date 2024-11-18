//===-- MiniLLVMContext.h ---------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_SOURCE_PLUGINS_TYPESYSTEM_MINILLVM_MINILLVMCONTEXT_H
#define LLDB_SOURCE_PLUGINS_TYPESYSTEM_MINILLVM_MINILLVMCONTEXT_H

#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"

namespace lldb_private {

enum class LongDoubleType {
  Float64,
  Float80, // 80bit x87 float
  Float128,
  DoubleDouble, // power pc 2xdouble for long double
};

enum class WCharType {
  SignedInt32,
  UnsignedInt16,
};

struct MiniLLVMTargetInfo {
  int intWidth, intAlign;
  int longWidth, longAlign;
  int longLongWidth, longLongAlign;
  int pointerWidth, pointerAlign;
  int int128Align;
  int longDoubleWidth;
  int longDoubleAlign;
  LongDoubleType longDoubleType;
  WCharType wcharType;
  const char *dataLayout;

  constexpr MiniLLVMTargetInfo()
      : intWidth(32), intAlign(32), longWidth(32), longAlign(32),
        longLongWidth(64), longLongAlign(64), pointerWidth(32),
        pointerAlign(32), int128Align(128), longDoubleWidth(64),
        longDoubleAlign(64), longDoubleType(LongDoubleType::Float64),
        wcharType(WCharType::SignedInt32), dataLayout("") {}
};

struct MiniLLVMContext {
  llvm::LLVMContext m_llvm_context;
  llvm::Module m_module;
  std::string m_triple;
  const MiniLLVMTargetInfo *targetInfo;
  
  MiniLLVMContext(llvm::StringRef name, llvm::Triple &triple);
};

} // namespace lldb_private

#endif // LLDB_SOURCE_PLUGINS_TYPESYSTEM_MINILLVM_MINILLVMCONTEXT_H
