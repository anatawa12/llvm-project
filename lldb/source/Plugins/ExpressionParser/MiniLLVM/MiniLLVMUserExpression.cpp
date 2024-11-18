//===-- MiniLLVMUserExpression.cpp
//-------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include <cstdio>
#include <sys/types.h>

#include <cstdlib>
#include <map>
#include <string>

#include "MiniLLVMCompiler.h"
#include "MiniLLVMUserExpression.h"
#include "Plugins/TypeSystem/MiniLLVM/TypeSystemMiniLLVM.h"
#include "lldb/Core/Module.h"
#include "lldb/Expression/DiagnosticManager.h"
#include "lldb/Expression/IRExecutionUnit.h"
#include "lldb/Expression/Materializer.h"
#include "lldb/Utility/LLDBLog.h"
#include "lldb/Utility/Log.h"

#include "llvm/BinaryFormat/Dwarf.h"
#include "llvm/IR/LLVMContext.h"

using namespace lldb_private;

char MiniLLVMUserExpression::ID;

MiniLLVMUserExpression::MiniLLVMUserExpression(
    ExecutionContextScope &exe_scope, llvm::StringRef expr,
    llvm::StringRef prefix, SourceLanguage language, ResultType desired_type,
    const EvaluateExpressionOptions &options, ValueObject *ctx_obj)
    : LLVMUserExpression(exe_scope, expr, prefix, language, desired_type,
                         options) {
  switch (m_language.name) {
  case llvm::dwarf::DW_LNAME_C_plus_plus:
    m_allow_cxx = true;
    break;
  case llvm::dwarf::DW_LNAME_ObjC:
    m_allow_objc = true;
    break;
  case llvm::dwarf::DW_LNAME_ObjC_plus_plus:
  default:
    m_allow_cxx = true;
    m_allow_objc = true;
    break;
  }
}

MiniLLVMUserExpression::~MiniLLVMUserExpression() = default;

void MiniLLVMUserExpression::ScanContext(ExecutionContext &exe_ctx,
                                         Status &err) {}

bool MiniLLVMUserExpression::PrepareForParsing(
    DiagnosticManager &diagnostic_manager, ExecutionContext &exe_ctx,
    bool for_completion) {

  if (m_options.GetExecutionPolicy() == eExecutionPolicyTopLevel) {
    // Toplevel: !mini-llvm
    m_transformed_text = m_expr_text;
  } else {
    // Non-Toplevel: !mini-llvm-expr <count of blocks>
    // for single expression.
    // no return is supported (for now)

    auto expr = llvm::StringRef(m_expr_text);
    llvm::StringRef heading;
    do {
      std::tie(heading, expr) = expr.split('\n');
    } while (heading.trim().empty());
    auto tokens = llvm::to_vector<3>(llvm::split(heading.trim(), ' '));
    if (tokens.size() != 2 || tokens[0] != "#!mini-llvm-expr") {
      diagnostic_manager.PutString(lldb::eSeverityError,
                                   "no #!mini-llvm-expr at start");
      return false;
    }
    int block_count;
    if (!llvm::to_integer(tokens[1], block_count)) {
      diagnostic_manager.PutString(lldb::eSeverityError,
                                   "block count must be a valid integer");
      return false;
    }
    if (block_count < 1) {
      diagnostic_manager.PutString(lldb::eSeverityError,
                                   "block count must be greater than 0");
      return false;
    }

    m_transformed_text =
        llvm::formatv("#!mini-llvm\n"
                      "{3}\n"
                      "define_function_type void {0}\n"
                      "define_function {0} {0} {1}\n"
                      "{2}",
                      FunctionName(), block_count, expr, m_expr_prefix);
  }

  InstallContext(exe_ctx);
  return true;
}

bool MiniLLVMUserExpression::TryParse(
    DiagnosticManager &diagnostic_manager, ExecutionContext &exe_ctx,
    lldb_private::ExecutionPolicy execution_policy, bool keep_result_in_memory,
    bool generate_debug_info) {
  m_materializer_up = std::make_unique<Materializer>();

  MiniLLVMCompiler compiler(diagnostic_manager);

  if (!compiler.ParseAndEmit(m_transformed_text)) {
    return false;
  }

  ConstString function_name;

  if (execution_policy != eExecutionPolicyTopLevel) {
    function_name = ConstString(FunctionName());
  }

  lldb_private::Status jit_error =
      compiler.Compile(function_name, m_jit_start_addr, m_jit_end_addr,
                       m_execution_unit_sp, exe_ctx);

  if (jit_error.Fail()) {
    const char *error_cstr = jit_error.AsCString();
    if (error_cstr && error_cstr[0])
      diagnostic_manager.PutString(lldb::eSeverityError, error_cstr);
    else
      diagnostic_manager.PutString(lldb::eSeverityError,
                                   "expression can't be interpreted or run");
    return false;
  }
  return true;
}

bool MiniLLVMUserExpression::Parse(
    DiagnosticManager &diagnostic_manager, ExecutionContext &exe_ctx,
    lldb_private::ExecutionPolicy execution_policy, bool keep_result_in_memory,
    bool generate_debug_info) {
  Log *log = GetLog(LLDBLog::Expressions);

  if (!PrepareForParsing(diagnostic_manager, exe_ctx, /*for_completion*/ false))
    return false;

  LLDB_LOGF(log, "Parsing the following code:\n%s", m_transformed_text.c_str());

  ////////////////////////////////////
  // Set up the target and compiler
  //

  Target *target = exe_ctx.GetTargetPtr();

  if (!target) {
    diagnostic_manager.PutString(lldb::eSeverityError, "invalid target");
    return false;
  }

  //////////////////////////
  // Parse the expression
  //

  bool parse_success = TryParse(diagnostic_manager, exe_ctx, execution_policy,
                                keep_result_in_memory, generate_debug_info);

  if (!parse_success)
    return false;

  if (m_execution_unit_sp) {
    bool register_execution_unit = false;

    if (m_options.GetExecutionPolicy() == eExecutionPolicyTopLevel) {
      register_execution_unit = true;
    }

    // If there is more than one external function in the execution unit, it
    // needs to keep living even if it's not top level, because the result
    // could refer to that function.

    if (m_execution_unit_sp->GetJittedFunctions().size() > 1) {
      register_execution_unit = true;
    }

    if (register_execution_unit) {
      if (auto *persistent_state =
              exe_ctx.GetTargetPtr()->GetPersistentExpressionStateForLanguage(
                  m_language.AsLanguageType()))
        persistent_state->RegisterExecutionUnit(m_execution_unit_sp);
    }
  }

  if (generate_debug_info) {
    lldb::ModuleSP jit_module_sp(m_execution_unit_sp->GetJITModule());

    if (jit_module_sp) {
      ConstString const_func_name(FunctionName());
      FileSpec jit_file;
      jit_file.SetFilename(const_func_name);
      jit_module_sp->SetFileSpecAndObjectName(jit_file, ConstString());
      m_jit_module_wp = jit_module_sp;
      target->GetImages().Append(jit_module_sp);
    }
  }

  Process *process = exe_ctx.GetProcessPtr();
  if (process && m_jit_start_addr != LLDB_INVALID_ADDRESS)
    m_jit_process_wp = lldb::ProcessWP(process->shared_from_this());
  return true;
}

bool MiniLLVMUserExpression::AddArguments(
    ExecutionContext &exe_ctx, std::vector<lldb::addr_t> &args,
    lldb::addr_t struct_address, DiagnosticManager &diagnostic_manager) {
  args.push_back(struct_address);
  return true;
}

lldb::ExpressionVariableSP
MiniLLVMUserExpression::GetResultAfterDematerialization(
    ExecutionContextScope *exe_scope) {
  return nullptr;
}
