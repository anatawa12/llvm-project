//===-- MiniLLVMUserExpression.h -----------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_SOURCE_PLUGINS_EXPRESSIONPARSER_MINILLVM_MINILLVMUSEREXPRESSION_H
#define LLDB_SOURCE_PLUGINS_EXPRESSIONPARSER_MINILLVM_MINILLVMUSEREXPRESSION_H

#include <optional>
#include <vector>

#include "lldb/Expression/LLVMUserExpression.h"
#include "lldb/Target/ExecutionContext.h"
#include "lldb/lldb-forward.h"
#include "lldb/lldb-private.h"

namespace lldb_private {

/// \class MiniLLVMUserExpression MiniLLVMUserExpression.h
/// "lldb/Expression/MiniLLVMUserExpression.h" Encapsulates a single expression
/// for use with MiniLLVM
///
/// LLDB uses expressions for various purposes, notably to call functions
/// and as a backend for the expr command.  MiniLLVMUserExpression encapsulates
/// the objects needed to parse and interpret or JIT an expression.  It uses
/// the MiniLLVM parser to produce LLVM IR from the expression.
class MiniLLVMUserExpression : public LLVMUserExpression {
  // LLVM RTTI support
  static char ID;

public:
  bool isA(const void *ClassID) const override {
    return ClassID == &ID || LLVMUserExpression::isA(ClassID);
  }
  static bool classof(const Expression *obj) { return obj->isA(&ID); }

  /// Constructor
  ///
  /// \param[in] expr
  ///     The expression to parse.
  ///
  /// \param[in] prefix
  ///     If non-NULL, a C string containing translation-unit level
  ///     definitions to be included when the expression is parsed.
  ///
  /// \param[in] language
  ///     If not unknown, a language to use when parsing the
  ///     expression.  Currently restricted to those languages
  ///     supported by MiniLLVM.
  ///
  /// \param[in] desired_type
  ///     If not eResultTypeAny, the type to use for the expression
  ///     result.
  ///
  /// \param[in] options
  ///     Additional options for the expression.
  ///
  /// \param[in] ctx_obj
  ///     The object (if any) in which context the expression
  ///     must be evaluated. For details see the comment to
  ///     `UserExpression::Evaluate`.
  MiniLLVMUserExpression(ExecutionContextScope &exe_scope, llvm::StringRef expr,
                      llvm::StringRef prefix, SourceLanguage language,
                      ResultType desired_type,
                      const EvaluateExpressionOptions &options,
                      ValueObject *ctx_obj,
                      const MiniLLVMContext *miniContext);

  ~MiniLLVMUserExpression() override;

  /// Parse the expression
  ///
  /// \param[in] diagnostic_manager
  ///     A diagnostic manager to report parse errors and warnings to.
  ///
  /// \param[in] exe_ctx
  ///     The execution context to use when looking up entities that
  ///     are needed for parsing (locations of functions, types of
  ///     variables, persistent variables, etc.)
  ///
  /// \param[in] execution_policy
  ///     Determines whether interpretation is possible or mandatory.
  ///
  /// \param[in] keep_result_in_memory
  ///     True if the resulting persistent variable should reside in
  ///     target memory, if applicable.
  ///
  /// \return
  ///     True on success (no errors); false otherwise.
  bool Parse(DiagnosticManager &diagnostic_manager, ExecutionContext &exe_ctx,
             lldb_private::ExecutionPolicy execution_policy,
             bool keep_result_in_memory, bool generate_debug_info) override;

  lldb::ExpressionVariableSP
  GetResultAfterDematerialization(ExecutionContextScope *exe_scope) override;

private:
  const MiniLLVMContext *m_mini_context;
  /// Populate m_in_cplusplus_method and m_in_objectivec_method based on the
  /// environment.

  /// Contains the actual parsing implementation.
  /// The parameter have the same meaning as in MiniLLVMUserExpression::Parse.
  /// \see MiniLLVMUserExpression::Parse
  bool TryParse(DiagnosticManager &diagnostic_manager,
                ExecutionContext &exe_ctx,
                lldb_private::ExecutionPolicy execution_policy,
                bool keep_result_in_memory, bool generate_debug_info);

  void ScanContext(ExecutionContext &exe_ctx,
                   lldb_private::Status &err) override;

  bool AddArguments(ExecutionContext &exe_ctx, std::vector<lldb::addr_t> &args,
                    lldb::addr_t struct_address,
                    DiagnosticManager &diagnostic_manager) override;

  bool PrepareForParsing(DiagnosticManager &diagnostic_manager,
                         ExecutionContext &exe_ctx, bool for_completion);
};

} // namespace lldb_private

#endif // LLDB_SOURCE_PLUGINS_EXPRESSIONPARSER_MINILLVM_MINILLVMUSEREXPRESSION_H
