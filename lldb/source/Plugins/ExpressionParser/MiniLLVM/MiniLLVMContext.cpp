//===-- MiniLLVMContext.cpp -------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "MiniLLVMContext.h"

#include "llvm/Support/FormatVariadic.h"
#include "llvm/TargetParser/Triple.h"

#include "lldb/Core/Debugger.h"
#include "lldb/Utility/LLDBLog.h"

using namespace lldb_private;

static const MiniLLVMTargetInfo defaultInfo = {};

static const MiniLLVMTargetInfo *
getTargetInfoForType(const llvm::Triple &triple) {
  if (triple.getArch() == llvm::Triple::aarch64) {
    if (triple.isOSDarwin()) {
      static MiniLLVMTargetInfo result{};
      result.longWidth = result.longAlign = 64;
      result.pointerWidth = result.pointerAlign = 64;
      result.longDoubleWidth = result.longDoubleAlign = 64;
      result.longDoubleType = LongDoubleType::Float64;
      result.wcharType = WCharType::SignedInt32;
      result.dataLayout = "e-m:o-p270:32:32-p271:32:32-p272:64:64-i64:64-"
                          "i128:128-n32:64-S128-Fn32";
      return &result;
    }
  }
  if (triple.getArch() == llvm::Triple::x86_64) {
    if (triple.isOSDarwin() || triple.isOSBinFormatMachO()) {
      static MiniLLVMTargetInfo result = {};
      result.longWidth = result.longAlign = 64;
      result.pointerWidth = result.pointerAlign = 64;
      result.longDoubleWidth = result.longDoubleAlign = 128;
      result.longDoubleType = LongDoubleType::Float80;
      result.wcharType = WCharType::SignedInt32;
      result.dataLayout = "e-m:o-p270:32:32-p271:32:32-p272:64:64-"
                          "i64:64-i128:128-f80:128-n8:16:32:64-S128";
      return &result;
    }
    switch (triple.getOS()) {
    case llvm::Triple::Linux: {
      if (!triple.isX32()) {
        static MiniLLVMTargetInfo result = {};
        result.longWidth = result.longAlign = 64;
        result.pointerWidth = result.pointerAlign = 64;
        result.longDoubleWidth = result.longDoubleAlign = 128;
        result.wcharType = WCharType::SignedInt32;
        result.dataLayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-"
                            "i128:128-f80:128-n8:16:32:64-S128";
        return &result;
      }
      break;
    }
    case llvm::Triple::Win32: {
      if (triple.getEnvironment() != llvm::Triple::Cygnus &&
          triple.getEnvironment() != llvm::Triple::GNU) {
        if (triple.isOSBinFormatCOFF()) {
          static MiniLLVMTargetInfo result = {};
          result.longWidth = result.longAlign = 32;
          result.pointerWidth = result.pointerAlign = 64;
          result.longDoubleWidth = result.longDoubleAlign = 64;
          result.longDoubleType = LongDoubleType::Float64;
          result.wcharType = WCharType::UnsignedInt16;
          result.dataLayout = "e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-"
                              "i128:128-f80:128-n8:16:32:64-S128";
          return &result;
        }
      }
      break;
    }
    default:
      break;
    }
  }
  return nullptr;
}

MiniLLVMContext::MiniLLVMContext(llvm::StringRef name, llvm::Triple &triple)
    : m_module(name, m_llvm_context) {

  m_triple = triple.str();
  m_module.setTargetTriple(m_triple);
  targetInfo = getTargetInfoForType(triple);

  if (targetInfo == nullptr) {
    targetInfo = &defaultInfo;
    std::string err =
        llvm::formatv(
            "Failed to initialize builtin MiniLLVM types for target '{0}'. "
            "Printing variables may behave unexpectedly.",
            m_triple)
            .str();

    LLDB_LOG(GetLog(LLDBLog::Expressions), err.c_str());

    static std::once_flag s_uninitialized_target_warning;
    Debugger::ReportWarning(std::move(err), /*debugger_id=*/std::nullopt,
                            &s_uninitialized_target_warning);
  } else {
    m_module.setDataLayout(targetInfo->dataLayout);
  }
}
