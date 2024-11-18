//===-- MiniLLVMCompiler.h --------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_SOURCE_PLUGINS_EXPRESSIONPARSER_MINILLVM_MINILLVMCOMPILER_H
#define LLDB_SOURCE_PLUGINS_EXPRESSIONPARSER_MINILLVM_MINILLVMCOMPILER_H

#include "Plugins/ExpressionParser/MiniLLVM/MiniLLVMContext.h"

#include "lldb/lldb-forward.h"
#include "lldb/lldb-private.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"

class MiniLLVMCompiler {
  lldb_private::DiagnosticManager &diagnostic_manager;
  std::unique_ptr<llvm::LLVMContext> context;
  std::unique_ptr<llvm::IRBuilder<>> builder;
  std::unique_ptr<llvm::Module> module;
  llvm::Function *current_fn = nullptr;
  std::vector<llvm::BasicBlock *> blocks;
  llvm::StringMap<llvm::Value *> named_values;
  llvm::StringMap<llvm::Type *> named_types;
  std::vector<
      std::tuple<llvm::PHINode *, llvm::BasicBlock *, llvm::StringRef, int>>
      phi_updates;
  int line_num;

  bool GetType(llvm::StringRef name, llvm::Type *&type);
  bool GetValue(llvm::StringRef name, llvm::Value *&value);
  bool GetInt(llvm::StringRef name, int &value);
  bool ParseLine(std::vector<llvm::StringRef> &tokens);

public:
  MiniLLVMCompiler(lldb_private::DiagnosticManager &diagnostic_manager,
                   const lldb_private::MiniLLVMContext *context);

  bool ParseAndEmit(llvm::StringRef text);
  lldb_private::Status Compile(llvm::StringRef target_name,
                               lldb::addr_t &func_addr, lldb::addr_t &func_end,
                               lldb::IRExecutionUnitSP &execution_unit_sp,
                               lldb_private::ExecutionContext &exe_ctx);
};

#endif
