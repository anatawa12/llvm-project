//===-- MiniLLVMUtilityFunction.h ----------------------------------*- C++
//-*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_SOURCE_PLUGINS_EXPRESSIONPARSER_MINILLVM_MINILLVMUTILITYFUNCTION_H
#define LLDB_SOURCE_PLUGINS_EXPRESSIONPARSER_MINILLVM_MINILLVMUTILITYFUNCTION_H

#include <map>
#include <string>
#include <vector>

#include "MiniLLVMContext.h"

#include "lldb/Expression/UtilityFunction.h"
#include "lldb/lldb-forward.h"
#include "lldb/lldb-private.h"

namespace lldb_private {

/// \class MiniLLVMUtilityFunction MiniLLVMUtilityFunction.h
/// "lldb/Expression/MiniLLVMUtilityFunction.h" Encapsulates a single expression
/// for use with Clang
///
/// LLDB uses expressions for various purposes, notably to call functions
/// and as a backend for the expr command.  MiniLLVMUtilityFunction encapsulates
/// a self-contained function meant to be used from other code.  Utility
/// functions can perform error-checking for ClangUserExpressions, or can
/// simply provide a way to push a function into the target for the debugger
/// to call later on.
class MiniLLVMUtilityFunction : public UtilityFunction {
  // LLVM RTTI support
  static char ID;

public:
  bool isA(const void *ClassID) const override {
    return ClassID == &ID || UtilityFunction::isA(ClassID);
  }
  static bool classof(const Expression *obj) { return obj->isA(&ID); }

  /// Constructor
  ///
  /// \param[in] text
  ///     The text of the function.  Must be a full translation unit.
  ///
  /// \param[in] name
  ///     The name of the function, as used in the text.
  ///
  /// \param[in] enable_debugging
  ///     Enable debugging of this function.
  MiniLLVMUtilityFunction(ExecutionContextScope &exe_scope, std::string text,
                          std::string name, bool enable_debugging,
                          const MiniLLVMContext *miniContext);

  ~MiniLLVMUtilityFunction() override;

  bool Install(DiagnosticManager &diagnostic_manager,
               ExecutionContext &exe_ctx) override;

private:
  const MiniLLVMContext *m_mini_context;
};

} // namespace lldb_private

#endif // LLDB_SOURCE_PLUGINS_EXPRESSIONPARSER_MINILLVM_MINILLVMUTILITYFUNCTION_H
