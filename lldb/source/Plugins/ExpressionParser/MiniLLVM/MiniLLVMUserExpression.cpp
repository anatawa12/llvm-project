//===-- MiniLLVMUserExpression.cpp -------------------------------------------===//
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

#include "MiniLLVMUserExpression.h"

#include "Plugins/TypeSystem/MiniLLVM/TypeSystemMiniLLVM.h"
#include "lldb/Expression/DiagnosticManager.h"
#include "lldb/Core/Debugger.h"
#include "lldb/Core/Module.h"
#include "lldb/Expression/ExpressionSourceCode.h"
#include "lldb/Expression/IRExecutionUnit.h"
#include "lldb/Expression/IRInterpreter.h"
#include "lldb/Expression/Materializer.h"
#include "lldb/Host/HostInfo.h"
#include "lldb/Symbol/Block.h"
#include "lldb/Symbol/CompileUnit.h"
#include "lldb/Symbol/Function.h"
#include "lldb/Symbol/ObjectFile.h"
#include "lldb/Symbol/SymbolFile.h"
#include "lldb/Symbol/SymbolVendor.h"
#include "lldb/Symbol/Type.h"
#include "lldb/Symbol/VariableList.h"
#include "lldb/Target/ExecutionContext.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/StackFrame.h"
#include "lldb/Target/Target.h"
#include "lldb/Target/ThreadPlan.h"
#include "lldb/Target/ThreadPlanCallUserExpression.h"
#include "lldb/Utility/ConstString.h"
#include "lldb/Utility/LLDBLog.h"
#include "lldb/Utility/Log.h"
#include "lldb/Utility/StreamString.h"
#include "lldb/ValueObject/ValueObjectConstResult.h"

#include "llvm/BinaryFormat/Dwarf.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"

using namespace lldb_private;

char MiniLLVMUserExpression::ID;

MiniLLVMUserExpression::MiniLLVMUserExpression(
    ExecutionContextScope &exe_scope, llvm::StringRef expr,
    llvm::StringRef prefix, SourceLanguage language, ResultType desired_type,
    const EvaluateExpressionOptions &options, ValueObject *ctx_obj)
    : LLVMUserExpression(exe_scope, expr, prefix, language, desired_type,
                         options),
      m_target_func_addr(LLDB_INVALID_ADDRESS) {
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

void MiniLLVMUserExpression::ScanContext(ExecutionContext &exe_ctx, Status &err) {
}

bool MiniLLVMUserExpression::PrepareForParsing(
    DiagnosticManager &diagnostic_manager, ExecutionContext &exe_ctx,
    bool for_completion) {
  InstallContext(exe_ctx);
  return true;
}

bool MiniLLVMUserExpression::TryParse(
    DiagnosticManager &diagnostic_manager, ExecutionContext &exe_ctx,
    lldb_private::ExecutionPolicy execution_policy, bool keep_result_in_memory,
    bool generate_debug_info) {
  // TOOD: This is subset of C instead of minillvm lang. reimplement this
  m_materializer_up = std::make_unique<Materializer>();

  // We only accept "((void (*)())(address))()", error otherwise
  std::string prefix_str = "((void (*)())(";
  std::string suffix_str = "))()";

  auto prefix_pos = m_expr_text.find("((void (*)())(");
  auto suffix_pos = m_expr_text.find("))()");
  if (prefix_pos == std::string::npos || suffix_pos == std::string::npos ||
      prefix_pos >= suffix_pos) {
    diagnostic_manager.PutString(
        lldb::eSeverityError,
        "expression must be a function call with a function pointer cast");
    return false;
  }

  std::string_view address_str =
      ((std::string_view)m_expr_text)
          .substr(prefix_pos + prefix_str.length(),
                  suffix_pos - prefix_pos - prefix_str.length());
  lldb::addr_t address;
  if (!llvm::to_integer(address_str, address)) {
    diagnostic_manager.PutString(lldb::eSeverityError,
                                 "address must be a valid integer");
    return false;
  }
  m_target_func_addr = address;

  // do JIT
  std::unique_ptr<llvm::LLVMContext> TheContext =
      std::make_unique<llvm::LLVMContext>();
  std::unique_ptr<llvm::IRBuilder<>> Builder =
      std::make_unique<llvm::IRBuilder<>>(*TheContext);
  std::unique_ptr<llvm::Module> TheModule =
      std::make_unique<llvm::Module>("top", *TheContext);
  lldb_private::Status err;

  unsigned ptr_size = 64;

  llvm::FunctionType *noArgReturnVoid =
      llvm::FunctionType::get(llvm::Type::getVoidTy(*TheContext), false);

  llvm::Function *mainFunc =
      llvm::Function::Create(noArgReturnVoid, llvm::Function::ExternalLinkage,
                             "main", TheModule.get());
  llvm::BasicBlock *mainBlock =
      llvm::BasicBlock::Create(*TheContext, "", mainFunc);
  Builder->SetInsertPoint(mainBlock);

  auto *func_ptr_ty = llvm::PointerType::get(noArgReturnVoid, 0);
  auto *func_addr_const = llvm::ConstantInt::get(*TheContext, llvm::APInt(ptr_size, address));
  auto *func_ptr_const = llvm::ConstantExpr::getIntToPtr(func_addr_const, func_ptr_ty);
  Builder->CreateCall(noArgReturnVoid, func_ptr_const);
  Builder->CreateRetVoid();

  SymbolContext sc;
  ConstString function_name("main");
  std::vector<std::string> target_feature;

  m_execution_unit_sp = std::make_shared<IRExecutionUnit>(
      TheContext, // handed off here
      TheModule,  // handed off here
      function_name, exe_ctx.GetTargetSP(), sc, target_feature);
  m_execution_unit_sp->GetRunnableInfo(err, m_jit_start_addr, m_jit_end_addr);

  if (err.Fail()) {
    diagnostic_manager.PutString(lldb::eSeverityError,
                                 "expression can't be interpreted or run");
    return false;
  }
  return true;
}

bool MiniLLVMUserExpression::Parse(DiagnosticManager &diagnostic_manager,
                                ExecutionContext &exe_ctx,
                                lldb_private::ExecutionPolicy execution_policy,
                                bool keep_result_in_memory,
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
#if CONSOLE_LOG_SAVER // shouldRetryWithCppModule will be false
  // If the expression failed to parse, check if retrying parsing with a loaded
  // C++ module is possible.
  if (!parse_success && shouldRetryWithCppModule(*target, execution_policy)) {
    // Load the loaded C++ modules.
    SetupCppModuleImports(exe_ctx);
    // If we did load any modules, then retry parsing.
    if (!m_imported_cpp_modules.empty()) {
      // Create a dedicated diagnostic manager for the second parse attempt.
      // These diagnostics are only returned to the caller if using the fallback
      // actually succeeded in getting the expression to parse. This prevents
      // that module-specific issues regress diagnostic quality with the
      // fallback mode.
      DiagnosticManager retry_manager;
      // The module imports are injected into the source code wrapper,
      // so recreate those.
      CreateSourceCode(retry_manager, exe_ctx, m_imported_cpp_modules,
                       /*for_completion*/ false);
      parse_success = TryParse(retry_manager, exe_ctx, execution_policy,
                               keep_result_in_memory, generate_debug_info);
      // Return the parse diagnostics if we were successful.
      if (parse_success)
        diagnostic_manager = std::move(retry_manager);
    }
  }
#endif
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

bool MiniLLVMUserExpression::AddArguments(ExecutionContext &exe_ctx,
                                       std::vector<lldb::addr_t> &args,
                                       lldb::addr_t struct_address,
                                       DiagnosticManager &diagnostic_manager) {
  args.push_back(struct_address);
  return true;
}

lldb::ExpressionVariableSP MiniLLVMUserExpression::GetResultAfterDematerialization(
    ExecutionContextScope *exe_scope) {
  return nullptr;
}
