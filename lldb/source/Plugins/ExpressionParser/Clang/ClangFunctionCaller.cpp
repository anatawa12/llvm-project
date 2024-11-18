//===-- ClangFunctionCaller.cpp -------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "ClangFunctionCaller.h"

#include "ASTStructExtractor.h"
#include "ClangExpressionParser.h"

#ifdef CONSOLE_LOG_SAVER
#include "clang/AST/ASTContext.h"
#include "clang/AST/RecordLayout.h"
#include "clang/CodeGen/CodeGenAction.h"
#include "clang/CodeGen/ModuleBuilder.h"
#include "clang/Frontend/CompilerInstance.h"
#endif // CONSOLE_LOG_SAVER
#include "llvm/ADT/StringRef.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/IR/Module.h"
#include "llvm/TargetParser/Triple.h"

#ifdef CONSOLE_LOG_SAVER
#include "Plugins/TypeSystem/Clang/TypeSystemClang.h"
#endif // CONSOLE_LOG_SAVER
#include "lldb/Core/Module.h"
#include "lldb/Expression/IRExecutionUnit.h"
#include "lldb/Interpreter/CommandReturnObject.h"
#include "lldb/Symbol/Function.h"
#include "lldb/Symbol/Type.h"
#include "lldb/Target/ExecutionContext.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/RegisterContext.h"
#include "lldb/Target/Target.h"
#include "lldb/Target/Thread.h"
#include "lldb/Target/ThreadPlan.h"
#include "lldb/Target/ThreadPlanCallFunction.h"
#include "lldb/Utility/DataExtractor.h"
#include "lldb/Utility/LLDBLog.h"
#include "lldb/Utility/Log.h"
#include "lldb/Utility/State.h"
#include "lldb/ValueObject/ValueObject.h"
#include "lldb/ValueObject/ValueObjectList.h"

#if !CONSOLE_LOG_SAVER
#include "lldb/Expression/DiagnosticManager.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"

// TODO: reimplement type system with llvm types
#include "clang/AST/Type.h"
#endif

using namespace lldb_private;

#if !CONSOLE_LOG_SAVER
namespace lldb_private {
class ClangFunctionCallerExpressionParser : public ExpressionParser {
public:
  ClangFunctionCallerExpressionParser(
      ExecutionContextScope *exe_scope, ClangFunctionCaller &expr,
      std::vector<CompilerType> argument_types)
      : ExpressionParser(exe_scope, expr, false),
        argument_types(argument_types) {}

  std::vector<CompilerType> argument_types;

  ~ClangFunctionCallerExpressionParser() override = default;

  bool Complete(CompletionRequest &request, unsigned line, unsigned pos,
                unsigned typed_pos) override {
    return false;
  }

  Status DoPrepareForExecution(
      lldb::addr_t &func_addr, lldb::addr_t &func_end,
      std::shared_ptr<IRExecutionUnit> &execution_unit_sp,
      lldb_private::ExecutionContext &exe_ctx, bool &can_interpret,
      lldb_private::ExecutionPolicy execution_policy) override {
    func_addr = LLDB_INVALID_ADDRESS;
    func_end = LLDB_INVALID_ADDRESS;

    ClangFunctionCaller &expr = static_cast<ClangFunctionCaller &>(m_expr);

    // do JIT
    std::unique_ptr<llvm::LLVMContext> context =
        std::make_unique<llvm::LLVMContext>();
    std::unique_ptr<llvm::IRBuilder<>> builder =
        std::make_unique<llvm::IRBuilder<>>(*context);
    std::unique_ptr<llvm::Module> module =
        std::make_unique<llvm::Module>("top", *context);
    lldb_private::Status err;

    // TODO: 32bit support
    unsigned ptr_size = 64;

    // region Create caller struct type
    std::vector<llvm::Type *> elements;
    // space for function pointer
    elements.push_back(llvm::PointerType::get(*context, 0));
    // space for arguments
    for (size_t i = 0; i < argument_types.size(); ++i) {
      // TODO: extend support for non pointers
      elements.push_back(llvm::PointerType::get(*context, 0));
    }
    // space for return value
    elements.push_back(llvm::PointerType::get(*context, 0));
    llvm::StructType *struct_type = llvm::StructType::create(
        *context, llvm::ArrayRef<llvm::Type *>(elements),
        llvm::StringRef(expr.m_wrapper_struct_name));
    // endregion

    // region Create Callee function type
    std::vector<llvm::Type *> arg_types;
    for (size_t i = 0; i < argument_types.size(); ++i) {
      arg_types.push_back(llvm::PointerType::get(*context, 0));
    }
    llvm::Type *return_type = llvm::PointerType::get(*context, 0);
    llvm::FunctionType *callee_func_type =
        llvm::FunctionType::get(return_type, arg_types, false);
    // endregion

    llvm::FunctionType *wrapper_func_type =
        llvm::FunctionType::get(llvm::Type::getVoidTy(*context),
                                llvm::PointerType::get(*context, 0), false);
    llvm::Function *wrapper_func = llvm::Function::Create(
        wrapper_func_type, llvm::Function::ExternalLinkage,
        expr.m_wrapper_function_name, module.get());
    wrapper_func->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Local);

    llvm::BasicBlock *mainBlock =
        llvm::BasicBlock::Create(*context, "", wrapper_func);
    builder->SetInsertPoint(mainBlock);
    auto *parameter = wrapper_func->args().begin();

    auto *function_ptr =
        builder->CreateLoad(llvm::PointerType::get(*context, 0), parameter);

    std::vector<llvm::Value *> args;
    for (size_t i = 0; i < argument_types.size(); ++i) {
      auto *arg_pointer = builder->CreateGEP(
          struct_type, 
          parameter,
          {builder->getIntN(ptr_size, 0), 
           builder->getInt32(i + 1)});
      // TODO: extend support for non pointers
      auto *arg_value =
          builder->CreateLoad(llvm::PointerType::get(*context, 0), arg_pointer);
      args.push_back(arg_value);
    }

    auto *return_value =
        builder->CreateCall(callee_func_type, function_ptr, args);

    auto *return_pointer = llvm::GetElementPtrInst::Create(
        struct_type, parameter,
        {builder->getIntN(ptr_size, 0),
         builder->getInt32(argument_types.size() + 1)});
        builder->Insert(return_pointer);
        builder->CreateStore(return_value, return_pointer);
    builder->CreateRetVoid();

    SymbolContext sc;
    ConstString function_name(expr.m_wrapper_function_name.c_str());
    std::vector<std::string> target_feature;

    execution_unit_sp = std::make_shared<IRExecutionUnit>(
        context,   // handed off here
        module, // handed off here
        function_name, exe_ctx.GetTargetSP(), sc, target_feature);
    execution_unit_sp->GetRunnableInfo(err, func_addr, func_end);

    return err;
  }
};
} // namespace lldb_private
#endif

char ClangFunctionCaller::ID;

// ClangFunctionCaller constructor
ClangFunctionCaller::ClangFunctionCaller(ExecutionContextScope &exe_scope,
                                         const CompilerType &return_type,
                                         const Address &functionAddress,
                                         const ValueList &arg_value_list,
                                         const char *name)
    : FunctionCaller(exe_scope, return_type, functionAddress, arg_value_list,
#ifdef CONSOLE_LOG_SAVER
                     name),
      m_type_system_helper(*this) {
#else
                     name) {
#endif
  m_jit_process_wp = lldb::ProcessWP(exe_scope.CalculateProcess());
  // Can't make a ClangFunctionCaller without a process.
  assert(m_jit_process_wp.lock());
}

// Destructor
ClangFunctionCaller::~ClangFunctionCaller() = default;

unsigned

ClangFunctionCaller::CompileFunction(lldb::ThreadSP thread_to_use_sp,
                                     DiagnosticManager &diagnostic_manager) {
  if (m_compiled)
    return 0;

  // Compilation might call code, make sure to keep on the thread the caller
  // indicated.
  ThreadList::ExpressionExecutionThreadPusher execution_thread_pusher(
      thread_to_use_sp);

#ifndef CONSOLE_LOG_SAVER
  uint32_t num_args = UINT32_MAX;
  bool trust_function = false;
  // GetArgumentCount returns -1 for an unprototyped function.
  CompilerType function_clang_type;
  if (m_function_ptr) {
    function_clang_type = m_function_ptr->GetCompilerType();
    if (function_clang_type) {
      int num_func_args = function_clang_type.GetFunctionArgumentCount();
      if (num_func_args >= 0) {
        trust_function = true;
        num_args = num_func_args;
      }
    }
  }

  if (num_args == UINT32_MAX)
    num_args = m_arg_values.GetSize();

  if ((m_function_return_type.GetTypeInfo() & lldb::eTypeIsPointer) == 0) {
    diagnostic_manager.Printf(lldb::eSeverityError,
                              "Only pointers are supported for now.");
    return 1;
  }

  std::vector<CompilerType> argument_types;

  for (size_t i = 0; i < num_args; i++) {
    CompilerType type_name;

    if (trust_function) {
      type_name = function_clang_type.GetFunctionArgumentTypeAtIndex(i);
    } else {
      type_name = m_arg_values.GetValueAtIndex(i)->GetCompilerType();
      if (!type_name) {
        diagnostic_manager.Printf(
            lldb::eSeverityError,
            "Could not determine type of input value %" PRIu64 ".",
            (uint64_t)i);
        return 1;
      }
    }
    // TODO: extend support for non pointers
    if ((m_function_return_type.GetTypeInfo() & lldb::eTypeIsPointer) == 0) {
      diagnostic_manager.Printf(lldb::eSeverityError,
                                "Only pointers are supported for now.");
      return 1;
    }
    argument_types.push_back(type_name);
  }

  {
    lldb::ProcessSP jit_process_sp(m_jit_process_wp.lock());
    if (jit_process_sp) {
      // TODO: 32bit support
      // TODO: non pointer support
      m_struct_size = (num_args + 2) * 8;
      m_return_offset = (num_args + 1) * 8;
      m_return_size = 8;

      for (unsigned field_index = 0,
                    num_fields = num_args + 2;
           field_index < num_fields; ++field_index) {
        uint64_t offset = (field_index) * 8;
        m_member_offsets.push_back(offset);
      }

      m_struct_valid = true;
    }
  }

  unsigned num_errors = 0;
#else
  // FIXME: How does clang tell us there's no return value?  We need to handle
  // that case.
  unsigned num_errors = 0;

  std::string return_type_str(
      m_function_return_type.GetTypeName().AsCString(""));

  // Cons up the function we're going to wrap our call in, then compile it...
  // We declare the function "extern "C"" because the compiler might be in C++
  // mode which would mangle the name and then we couldn't find it again...
  m_wrapper_function_text.clear();
  m_wrapper_function_text.append("extern \"C\" void ");
  m_wrapper_function_text.append(m_wrapper_function_name);
  m_wrapper_function_text.append(" (void *input)\n{\n    struct ");
  m_wrapper_function_text.append(m_wrapper_struct_name);
  m_wrapper_function_text.append(" \n  {\n");
  m_wrapper_function_text.append("    ");
  m_wrapper_function_text.append(return_type_str);
  m_wrapper_function_text.append(" (*fn_ptr) (");

  // Get the number of arguments.  If we have a function type and it is
  // prototyped, trust that, otherwise use the values we were given.

  // FIXME: This will need to be extended to handle Variadic functions.  We'll
  // need
  // to pull the defined arguments out of the function, then add the types from
  // the arguments list for the variable arguments.

  uint32_t num_args = UINT32_MAX;
  bool trust_function = false;
  // GetArgumentCount returns -1 for an unprototyped function.
  CompilerType function_clang_type;
  if (m_function_ptr) {
    function_clang_type = m_function_ptr->GetCompilerType();
    if (function_clang_type) {
      int num_func_args = function_clang_type.GetFunctionArgumentCount();
      if (num_func_args >= 0) {
        trust_function = true;
        num_args = num_func_args;
      }
    }
  }

  if (num_args == UINT32_MAX)
    num_args = m_arg_values.GetSize();

  std::string args_buffer; // This one stores the definition of all the args in
                           // "struct caller".
  std::string args_list_buffer; // This one stores the argument list called from
                                // the structure.
  for (size_t i = 0; i < num_args; i++) {
    std::string type_name;

    if (trust_function) {
      type_name = function_clang_type.GetFunctionArgumentTypeAtIndex(i)
                      .GetTypeName()
                      .AsCString("");
    } else {
      CompilerType clang_qual_type =
          m_arg_values.GetValueAtIndex(i)->GetCompilerType();
      if (clang_qual_type) {
        type_name = clang_qual_type.GetTypeName().AsCString("");
      } else {
        diagnostic_manager.Printf(
            lldb::eSeverityError,
            "Could not determine type of input value %" PRIu64 ".",
            (uint64_t)i);
        return 1;
      }
    }

    m_wrapper_function_text.append(type_name);
    if (i < num_args - 1)
      m_wrapper_function_text.append(", ");

    char arg_buf[32];
    args_buffer.append("    ");
    args_buffer.append(type_name);
    snprintf(arg_buf, 31, "arg_%" PRIu64, (uint64_t)i);
    args_buffer.push_back(' ');
    args_buffer.append(arg_buf);
    args_buffer.append(";\n");

    args_list_buffer.append("__lldb_fn_data->");
    args_list_buffer.append(arg_buf);
    if (i < num_args - 1)
      args_list_buffer.append(", ");
  }
  m_wrapper_function_text.append(
      ");\n"); // Close off the function calling prototype.

  m_wrapper_function_text.append(args_buffer);

  m_wrapper_function_text.append("    ");
  m_wrapper_function_text.append(return_type_str);
  m_wrapper_function_text.append(" return_value;");
  m_wrapper_function_text.append("\n  };\n  struct ");
  m_wrapper_function_text.append(m_wrapper_struct_name);
  m_wrapper_function_text.append("* __lldb_fn_data = (struct ");
  m_wrapper_function_text.append(m_wrapper_struct_name);
  m_wrapper_function_text.append(" *) input;\n");

  m_wrapper_function_text.append(
      "  __lldb_fn_data->return_value = __lldb_fn_data->fn_ptr (");
  m_wrapper_function_text.append(args_list_buffer);
  m_wrapper_function_text.append(");\n}\n");

  Log *log = GetLog(LLDBLog::Expressions);
  LLDB_LOGF(log, "Expression: \n\n%s\n\n", m_wrapper_function_text.c_str());

#endif
  // Okay, now compile this expression

  lldb::ProcessSP jit_process_sp(m_jit_process_wp.lock());
  if (jit_process_sp) {
    const bool generate_debug_info = true;
#if !CONSOLE_LOG_SAVER
    auto *clang_parser = new ClangFunctionCallerExpressionParser(
        jit_process_sp.get(), *this, argument_types);
    num_errors = 0;
#else
    auto *clang_parser = new ClangExpressionParser(jit_process_sp.get(), *this,
                                                   generate_debug_info);
    num_errors = clang_parser->Parse(diagnostic_manager);
#endif
    m_parser.reset(clang_parser);
  } else {
    diagnostic_manager.PutString(lldb::eSeverityError,
                                 "no process - unable to inject function");
    num_errors = 1;
  }

  m_compiled = (num_errors == 0);

  if (!m_compiled)
    return num_errors;

  return num_errors;
}

#ifdef CONSOLE_LOG_SAVER
char ClangFunctionCaller::ClangFunctionCallerHelper::ID;

clang::ASTConsumer *
ClangFunctionCaller::ClangFunctionCallerHelper::ASTTransformer(
    clang::ASTConsumer *passthrough) {
  m_struct_extractor = std::make_unique<ASTStructExtractor>(
      passthrough, m_owner.GetWrapperStructName(), m_owner);

  return m_struct_extractor.get();
}
#endif
