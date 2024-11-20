//===-- MiniLLVMCompiler.cpp ----------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef CONSOLE_LOG_SAVER

#include "MiniLLVMCompiler.h"

#include "lldb/Expression/DiagnosticManager.h"
#include "lldb/Expression/IRExecutionUnit.h"
#include "llvm/ADT/StringExtras.h"

#include "lldb/Target/Process.h"
#include "lldb/Target/Target.h"

using namespace llvm;

bool MiniLLVMCompiler::GetType(llvm::StringRef name, llvm::Type *&type) {
  if (named_types.find(name) == named_types.end()) {
    diagnostic_manager.Printf(lldb::eSeverityError,
                              "unknown type: %.*s at line %d", (int)name.size(),
                              name.bytes_begin(), line_num);
    return false;
  }
  type = named_types[name];
  return true;
}

bool MiniLLVMCompiler::GetValue(llvm::StringRef name, llvm::Value *&value) {
  if (named_values.find(name) == named_values.end()) {
    diagnostic_manager.Printf(lldb::eSeverityError,
                              "unknown value: %.*s at line %d",
                              (int)name.size(), name.bytes_begin(), line_num);
    return false;
  }
  value = named_values[name];
  return true;
}

bool MiniLLVMCompiler::GetInt(llvm::StringRef name, int &value) {
  if (!to_integer(name, value)) {
    diagnostic_manager.Printf(lldb::eSeverityError,
                              "invalid integer: %.*s at line %d",
                              (int)name.size(), name.bytes_begin(), line_num);
    return false;
  }
  return true;
}

bool MiniLLVMCompiler::GetToken(std::vector<llvm::StringRef> &tokens,
                                llvm::StringRef insn, int index,
                                llvm::StringRef &value) {
  if ((size_t)index >= tokens.size()) {
    diagnostic_manager.Printf(lldb::eSeverityError,
                              "missing argument for %.*s at line %d",
                              (int)insn.size(), insn.bytes_begin(), line_num);
    return false;
  }
  value = tokens[index];
  return true;
}

MiniLLVMCompiler::MiniLLVMCompiler(
    lldb_private::DiagnosticManager &diagnostic_manager,
    const lldb_private::MiniLLVMContext *miniContext)
    : diagnostic_manager(diagnostic_manager) {
  context = std::make_unique<LLVMContext>();
  builder = std::make_unique<IRBuilder<>>(*context);
  module = std::make_unique<Module>("mini-llvm-compiled", *context);
  module->setTargetTriple(miniContext->m_triple);
  if (miniContext->targetInfo) {
    module->setDataLayout(miniContext->targetInfo->dataLayout);
  }

  // built-in types
  named_types["void"] = Type::getVoidTy(*context);
  named_types["ptr"] = PointerType::get(*context, 0);
  named_types["i8"] = Type::getInt8Ty(*context);
  named_types["i1"] = Type::getInt1Ty(*context);
  named_types["i16"] = Type::getInt16Ty(*context);
  named_types["i32"] = Type::getInt32Ty(*context);
  named_types["i64"] = Type::getInt64Ty(*context);
  named_types["iptr"] = Type::getInt64Ty(*context); // TODO: 32bit support

  // built-in values
  named_values["null"] =
      ConstantPointerNull::get(cast<PointerType>(named_types["ptr"]));
  named_values["false"] = ConstantInt::getFalse(*context);
  named_values["true"] = ConstantInt::getTrue(*context);

  // built-in function
  { // llvm.memcpy.p0.p0.iptr
    auto *type = FunctionType::get(named_types["void"],
                                   {named_types["ptr"], named_types["ptr"],
                                    named_types["iptr"], named_types["i1"]},
                                   false);
    named_types["llvm.memcpy.p0.p0.iptr"] = type;

    // TODO: 32bit support: we need to change to "llvm.memcpy.p0.p0.i32"
    named_values["llvm.memcpy.p0.p0.iptr"] = Function::Create(
        type, Function::ExternalLinkage, "llvm.memcpy.p0.p0.i64", module.get());
  }
}

bool MiniLLVMCompiler::ParseAndEmit(llvm::StringRef text) {
  StringRef heading;
  do {
    std::tie(heading, text) = text.split('\n');
  } while (heading.trim().empty());
  if (heading.trim() != "#!mini-llvm") {
    diagnostic_manager.PutString(lldb::eSeverityError,
                                 "text must start with #!mini-llvm");
    return false;
  }

  int line_num_next = 1;
  for (const auto &line : split(text, '\n')) {
    line_num = line_num_next++;
    auto [main, _] = line.split(';');

    std::vector<StringRef> tokens;
    for (const auto &item : split(main, ' ')) {
      if (item.empty())
        continue;
      tokens.push_back(item.trim());
    }
    // empty line
    if (tokens.size() == 0)
      continue;

    if (!ParseLine(tokens)) {
      return false;
    }
  }

  for (const auto &[phi, block, value_name, phi_line_num] : phi_updates) {
    auto value = named_values.find(value_name);
    if (value == named_values.end()) {
      diagnostic_manager.Printf(
          lldb::eSeverityError, "unknown value: %.*s at line %d",
          (int)value_name.size(), value_name.bytes_begin(), phi_line_num);
      return false;
    }
    phi->addIncoming(value->second, block);
  }

  return true;
}

#define MLGetToken(index, value)                                               \
  llvm::StringRef value;                                                       \
  if (!GetToken(tokens, insn, index, value))                                   \
    return false;

#define MLGetType(index, type)                                                 \
  Type *type;                                                                  \
  {                                                                            \
    MLGetToken(index, _token);                                                 \
    if (!GetType(_token, type))                                                \
      return false;                                                            \
  }

#define MLGetValue(index, value)                                               \
  Value *value;                                                                \
  {                                                                            \
    MLGetToken(index, _token);                                                 \
    if (!GetValue(_token, value))                                              \
      return false;                                                            \
  }

#define MLGetInt(index, value)                                                 \
  int value;                                                                   \
  {                                                                            \
    MLGetToken(index, _token);                                                 \
    if (!GetInt(_token, value))                                                \
      return false;                                                            \
  }

bool MiniLLVMCompiler::ParseLine(std::vector<StringRef> &tokens) {
  auto insn = tokens.at(0);
  if (insn == "const") {
    MLGetToken(1, name);
    MLGetType(2, type);
    Value *value;
    if (type == named_types["ptr"]) {
      int bit_width = 64; // TODO: 32bit support
      auto *constant = ConstantInt::get(named_types["iptr"],
                                        APInt(bit_width, tokens.at(3), 10));
      value = llvm::ConstantExpr::getIntToPtr(constant, type);
    } else {
      value =
          ConstantInt::get(type, APInt(cast<IntegerType>(type)->getBitWidth(),
                                       tokens.at(3), 10));
    }
    named_values[name] = value;
  }

  else if (insn == "define_struct") {
    MLGetToken(1, name);
    std::vector<llvm::Type *> types;

    for (size_t i = 2; i < tokens.size(); i++) {
      MLGetType(i, type);
      types.push_back(type);
    }

    auto *new_type =
        StructType::create(*context, ArrayRef<Type *>(types), name);
    named_types[name] = new_type;
  } else if (insn == "define_function_type") {
    MLGetType(1, return_type);
    MLGetToken(2, function_type_name);
    std::vector<llvm::Type *> types;

    for (size_t i = 3; i < tokens.size(); i++) {
      MLGetType(i, type);
      types.push_back(type);
    }

    auto *function_type =
        FunctionType::get(return_type, ArrayRef<Type *>(types), false);

    named_types[function_type_name] = function_type;
  } else if (insn == "declare_function") {
    MLGetType(1, function_type);
    MLGetToken(2, function_name);

    auto *function = Function::Create(cast<FunctionType>(function_type),
                                      Function::ExternalLinkage, function_name,
                                      module.get());
    named_values[function_name] = function;
  } else if (insn == "define_function") {
    MLGetType(1, function_type);
    MLGetToken(2, function_name);
    MLGetInt(3, block_count);
    if (block_count == 0) {
      diagnostic_manager.Printf(
          lldb::eSeverityError,
          "function must have at least one block at line %d", line_num);
      return false;
    }

    current_fn = Function::Create(cast<FunctionType>(function_type),
                                  Function::ExternalLinkage, function_name,
                                  module.get());
    named_values[function_name] = current_fn;
    for (size_t i = 0; i < current_fn->arg_size(); i++) {
      auto name = std::string("%") + std::to_string(i);
      named_values[name] = current_fn->getArg(i);
    }

    blocks.clear();
    for (int i = 0; i < block_count; i++) {
      blocks.push_back(BasicBlock::Create(*context, "", current_fn));
    }

    builder->SetInsertPoint(blocks.at(0));

    // instruction builder
  } else if (insn == "begin_block") {
    MLGetInt(1, block_num);
    if (blocks.size() <= (size_t)block_num) {
      if (blocks.size() == 0) {
        diagnostic_manager.Printf(
            lldb::eSeverityError,
            "no functions are defining but begin_block is there at line %d",
            line_num);

      } else {
        diagnostic_manager.Printf(lldb::eSeverityError,
                                  "block index out of range at line %d: block "
                                  "count %d but creating %d",
                                  line_num, (int)blocks.size(), block_num);
      }
      return false;
    }
    builder->SetInsertPoint(blocks.at(block_num));
  }
  // basic instruction format for instructions
  // <insn> [result] <op1> <op2> ...
  else if (insn == "icmp") {
    MLGetToken(1, result);
    MLGetToken(2, op);
    ICmpInst::Predicate pred;
    if (op == "eq") {
      pred = ICmpInst::Predicate::ICMP_EQ;
    } else if (op == "ne") {
      pred = ICmpInst::Predicate::ICMP_NE;
    } else if (op == "slt") {
      pred = ICmpInst::Predicate::ICMP_SLT;
    } else if (op == "sle") {
      pred = ICmpInst::Predicate::ICMP_SLE;
    } else if (op == "sgt") {
      pred = ICmpInst::Predicate::ICMP_SGT;
    } else if (op == "sge") {
      pred = ICmpInst::Predicate::ICMP_SGE;
    } else {
      diagnostic_manager.Printf(lldb::eSeverityError,
                                "unknown predicate %.*s at line %d",
                                (int)op.size(), op.bytes_begin(), line_num);
      return false;
    }
    MLGetValue(3, op1);
    MLGetValue(4, op2);

    named_values[result] = builder->CreateICmp(pred, op1, op2);
  } else if (insn == "call") {
    MLGetToken(1, result);
    MLGetType(2, function_type_raw);
    MLGetValue(3, function);
    std::vector<Value *> values;
    for (size_t i = 4; i < tokens.size(); i++) {
      MLGetValue(i, value);
      values.push_back(value);
    }

    auto *function_type = cast<FunctionType>(function_type_raw);

    if (values.size() != function_type->getNumParams() &&
        (!function_type->isVarArg() ||
         values.size() <= function_type->getNumParams())) {
      diagnostic_manager.Printf(
          lldb::eSeverityError,
          "Calling a function with bad signature at line %d: argument count",
          line_num);
      return false;
    }

    for (unsigned i = 0; i != values.size(); ++i) {
      if (i < function_type->getNumParams() &&
          function_type->getParamType(i) != values[i]->getType()) {
        diagnostic_manager.Printf(
            lldb::eSeverityError,
            "Calling a function with a bad signature at line %d: argument %d",
            line_num, i);
        return false;
      }
    }

    named_values[result] =
        builder->CreateCall(function_type, function, ArrayRef<Value *>(values));
  } else if (insn == "store") {
    MLGetValue(1, value);
    MLGetValue(2, ptr);
    builder->CreateStore(value, ptr);
  } else if (insn == "load") {
    MLGetToken(1, result);
    MLGetType(2, type);
    MLGetValue(3, ptr);
    named_values[result] = builder->CreateLoad(type, ptr);
  } else if (insn == "add") {
    MLGetToken(1, result);
    MLGetValue(2, op1);
    MLGetValue(3, op2);
    named_values[result] = builder->CreateAdd(op1, op2);
  } else if (insn == "getelementptr") {
    MLGetToken(1, result);
    MLGetType(2, type);
    MLGetValue(3, ptr);
    MLGetValue(4, idx);
    if (tokens.size() == 6) {
      MLGetValue(5, idx2);
      named_values[result] = builder->CreateGEP(type, ptr, {idx, idx2});
    } else {
      named_values[result] = builder->CreateGEP(type, ptr, idx);
    }
  } else if (insn == "phi") {
    MLGetToken(1, result);
    MLGetType(2, type);
    MLGetInt(3, block_count);
    auto *phi = builder->CreatePHI(type, block_count);
    named_values[result] = phi;

    int base = 4;
    for (int i = 0; i < block_count; i++) {
      MLGetToken(base + i * 2, value_name);
      MLGetInt(base + i * 2 + 1, block_idx);
      auto *block = blocks.at(block_idx);
      phi_updates.push_back({phi, block, value_name, line_num});
    }
  }

  // trailing insns
  else if (insn == "cond_br") {
    MLGetValue(1, cond);
    MLGetInt(2, true_block_idx);
    MLGetInt(3, false_block_idx);
    auto *true_block = blocks.at(true_block_idx);
    auto *false_block = blocks.at(false_block_idx);
    builder->CreateCondBr(cond, true_block, false_block);
  } else if (insn == "br") {
    MLGetInt(1, block_idx);
    auto *block = blocks.at(block_idx);
    builder->CreateBr(block);
  } else if (insn == "ret") {
    MLGetValue(1, value);
    builder->CreateRet(value);
  } else if (insn == "ret_void") {
    builder->CreateRetVoid();
  } else {
    diagnostic_manager.Printf(lldb::eSeverityError,
                              "unknown instruction: %.*s at line %d",
                              (int)insn.size(), insn.bytes_begin(), line_num);
    return false;
  }

  return true;
}

lldb_private::Status
MiniLLVMCompiler::Compile(StringRef target_name, lldb::addr_t &func_addr,
                          lldb::addr_t &func_end,
                          lldb::IRExecutionUnitSP &execution_unit_sp,
                          lldb_private::ExecutionContext &exe_ctx) {
  lldb_private::SymbolContext sc;
  lldb_private::ConstString function_name(target_name);
  std::vector<std::string> target_feature;

  if (lldb::StackFrameSP frame_sp = exe_ctx.GetFrameSP()) {
    sc = frame_sp->GetSymbolContext(lldb::eSymbolContextEverything);
  } else if (lldb::TargetSP target_sp = exe_ctx.GetTargetSP()) {
    sc.target_sp = target_sp;
  }

  execution_unit_sp = std::make_shared<lldb_private::IRExecutionUnit>(
      context, // handed off here
      module,  // handed off here
      function_name, exe_ctx.GetTargetSP(), sc, target_feature);

  lldb_private::Status err;
  execution_unit_sp->GetRunnableInfo(err, func_addr, func_end);
  return err;
}

#endif
