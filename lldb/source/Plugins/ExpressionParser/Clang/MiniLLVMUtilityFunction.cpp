//===-- MiniLLVMUtilityFunction.cpp ---------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef CONSOLE_LOG_SAVER

#include "MiniLLVMUtilityFunction.h"
#include "MiniLLVMCompiler.h"

#include "lldb/Core/Module.h"
#include "lldb/Expression/DiagnosticManager.h"
#include "lldb/Expression/IRExecutionUnit.h"
#include "lldb/Target/ExecutionContext.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/Target.h"
#include "lldb/Utility/ConstString.h"
#include "lldb/Utility/Stream.h"

#include "llvm/IR/LLVMContext.h"

using namespace lldb_private;

char MiniLLVMUtilityFunction::ID;

MiniLLVMUtilityFunction::MiniLLVMUtilityFunction(
    ExecutionContextScope &exe_scope, std::string text, std::string name,
    bool enable_debugging)
    : UtilityFunction(exe_scope, text, std::move(name), enable_debugging) {}

MiniLLVMUtilityFunction::~MiniLLVMUtilityFunction() = default;

/// Install the utility function into a process
///
/// \param[in] diagnostic_manager
///     A diagnostic manager to report errors and warnings to.
///
/// \param[in] exe_ctx
///     The execution context to install the utility function to.
///
/// \return
///     True on success (no errors); false otherwise.
bool MiniLLVMUtilityFunction::Install(DiagnosticManager &diagnostic_manager,
                                      ExecutionContext &exe_ctx) {
  if (m_jit_start_addr != LLDB_INVALID_ADDRESS) {
    diagnostic_manager.PutString(lldb::eSeverityWarning, "already installed");
    return false;
  }

  ////////////////////////////////////
  // Set up the target and compiler
  //

  Target *target = exe_ctx.GetTargetPtr();

  if (!target) {
    diagnostic_manager.PutString(lldb::eSeverityError, "invalid target");
    return false;
  }

  Process *process = exe_ctx.GetProcessPtr();

  if (!process) {
    diagnostic_manager.PutString(lldb::eSeverityError, "invalid process");
    return false;
  }

  // Since we might need to call allocate memory and maybe call code to make
  // the caller, we need to be stopped.
  if (process->GetState() != lldb::eStateStopped) {
    diagnostic_manager.PutString(lldb::eSeverityError, "process running");
    return false;
  }

  //////////////////////////
  // Parse the expression
  //

  // bool keep_result_in_memory = false;

  const bool generate_debug_info = true;

  MiniLLVMCompiler compiler(diagnostic_manager);

  if (!compiler.ParseAndEmit(m_function_text)) {
    return false;
  }

  // bool can_interpret = false; // should stay that way
  lldb_private::Status jit_error =
      compiler.Compile(FunctionName(), m_jit_start_addr, m_jit_end_addr,
                       m_execution_unit_sp, exe_ctx);

  if (m_jit_start_addr != LLDB_INVALID_ADDRESS) {
    m_jit_process_wp = process->shared_from_this();
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
  }

  if (jit_error.Success()) {
    return true;
  } else {
    const char *error_cstr = jit_error.AsCString();
    if (error_cstr && error_cstr[0]) {
      diagnostic_manager.Printf(lldb::eSeverityError, "%s", error_cstr);
    } else {
      diagnostic_manager.PutString(lldb::eSeverityError,
                                   "expression can't be interpreted or run");
    }
    return false;
  }
}

#endif
