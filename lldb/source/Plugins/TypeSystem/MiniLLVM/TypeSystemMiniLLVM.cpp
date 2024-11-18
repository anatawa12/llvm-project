//===-- TypeSystemMiniLLVM.cpp
//-----------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "TypeSystemMiniLLVM.h"

#include "clang/AST/DeclBase.h"
#include "clang/AST/ExprCXX.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/FormatAdapters.h"
#include "llvm/Support/FormatVariadic.h"

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "llvm/ADT/APFloat.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/TypedPointerType.h"
#include "llvm/Support/Signals.h"
#include "llvm/Support/Threading.h"

#include "Plugins/ExpressionParser/Clang/ClangASTImporter.h"
#include "Plugins/ExpressionParser/Clang/ClangASTMetadata.h"
#include "Plugins/ExpressionParser/Clang/ClangExternalASTSourceCallbacks.h"
#include "Plugins/ExpressionParser/Clang/ClangFunctionCaller.h"
#include "Plugins/ExpressionParser/Clang/ClangPersistentVariables.h"
#include "Plugins/ExpressionParser/Clang/ClangUserExpression.h"
#include "Plugins/ExpressionParser/Clang/ClangUtil.h"
#include "Plugins/ExpressionParser/Clang/ClangUtilityFunction.h"
#include "lldb/Core/Debugger.h"
#include "lldb/Core/DumpDataExtractor.h"
#include "lldb/Core/Module.h"
#include "lldb/Core/PluginManager.h"
#include "lldb/Core/UniqueCStringMap.h"
#include "lldb/Host/StreamFile.h"
#include "lldb/Symbol/ObjectFile.h"
#include "lldb/Symbol/SymbolFile.h"
#include "lldb/Target/ExecutionContext.h"
#include "lldb/Target/Language.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/Target.h"
#include "lldb/Utility/ArchSpec.h"
#include "lldb/Utility/DataExtractor.h"
#include "lldb/Utility/Flags.h"
#include "lldb/Utility/LLDBAssert.h"
#include "lldb/Utility/LLDBLog.h"
#include "lldb/Utility/RegularExpression.h"
#include "lldb/Utility/Scalar.h"
#include "lldb/Utility/ThreadSafeDenseMap.h"

#include "Plugins/LanguageRuntime/ObjC/ObjCLanguageRuntime.h"
#include "Plugins/SymbolFile/DWARF/DWARFASTParserClang.h"

#include <cstdio>

#include <mutex>
#include <optional>

#include "Plugins/ExpressionParser/MiniLLVM/MiniLLVMUtilityFunction.h"

using namespace lldb;
using namespace lldb_private;
using namespace lldb_private::dwarf;
using namespace lldb_private::plugin::dwarf;
using llvm::StringSwitch;

LLDB_PLUGIN_DEFINE(TypeSystemMiniLLVM)

namespace {

static inline bool
TypeSystemMiniLLVMSupportsLanguage(lldb::LanguageType language) {
  return language == eLanguageTypeMiniLLVM;
}

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

} // namespace

namespace lldb_private {

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
        wcharType(WCharType::SignedInt32),
        dataLayout("") {}
};

static const MiniLLVMTargetInfo defaultInfo = {};

static MiniLLVMTargetInfo *getTargetInfoForType(const llvm::Triple &triple) {
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

struct MiniLLVMContext {
  llvm::LLVMContext m_llvm_context;
  llvm::Module m_module;
  std::string m_triple;
  const MiniLLVMTargetInfo *targetInfo;

  MiniLLVMContext(llvm::StringRef name, llvm::Triple &triple)
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
};

} // namespace lldb_private

char TypeSystemMiniLLVM::ID;

TypeSystemMiniLLVM::TypeSystemMiniLLVM(llvm::StringRef name,
                                       llvm::Triple target_triple) {
  m_display_name = name.str();
  if (!target_triple.str().empty())
    SetTargetTriple(target_triple.str());
  // The caller didn't pass an MiniLLVMContext so create a new one for this
  // TypeSystemMiniLLVM.
  CreateLLVMContext();

  LogCreation();
}

TypeSystemMiniLLVM::TypeSystemMiniLLVM(llvm::StringRef name,
                                       MiniLLVMContext &existing_ctxt) {
  m_display_name = name.str();
  SetTargetTriple(existing_ctxt.m_triple);

  m_context.reset(&existing_ctxt);

  LogCreation();
}

// Destructor
TypeSystemMiniLLVM::~TypeSystemMiniLLVM() { Finalize(); }

lldb::TypeSystemSP TypeSystemMiniLLVM::CreateInstance(
    lldb::LanguageType language, lldb_private::Module *module, Target *target) {
  if (!TypeSystemMiniLLVMSupportsLanguage(language))
    return lldb::TypeSystemSP();
  ArchSpec arch;
  if (module)
    arch = module->GetArchitecture();
  else if (target)
    arch = target->GetArchitecture();

  if (!arch.IsValid())
    return lldb::TypeSystemSP();

  llvm::Triple triple = arch.GetTriple();
  // LLVM wants this to be set to iOS or MacOSX; if we're working on
  // a bare-boards type image, change the triple for llvm's benefit.
  if (triple.getVendor() == llvm::Triple::Apple &&
      triple.getOS() == llvm::Triple::UnknownOS) {
    if (triple.getArch() == llvm::Triple::arm ||
        triple.getArch() == llvm::Triple::aarch64 ||
        triple.getArch() == llvm::Triple::aarch64_32 ||
        triple.getArch() == llvm::Triple::thumb) {
      triple.setOS(llvm::Triple::IOS);
    } else {
      triple.setOS(llvm::Triple::MacOSX);
    }
  }

  if (module) {
    std::string ast_name =
        "ASTContext for '" + module->GetFileSpec().GetPath() + "'";
    return std::make_shared<TypeSystemMiniLLVM>(ast_name, triple);
  }
  if (target && target->IsValid())
    return std::make_shared<ScratchTypeSystemMiniLLVM>(*target, triple);
  return lldb::TypeSystemSP();
}

LanguageSet TypeSystemMiniLLVM::GetSupportedLanguagesForTypes() {
  LanguageSet languages;
  languages.Insert(lldb::eLanguageTypeMiniLLVM);
  return languages;
}

LanguageSet TypeSystemMiniLLVM::GetSupportedLanguagesForExpressions() {
  LanguageSet languages;
  languages.Insert(lldb::eLanguageTypeMiniLLVM);
  return languages;
}

void TypeSystemMiniLLVM::Initialize() {
  PluginManager::RegisterPlugin(
      GetPluginNameStatic(), "minllvm base AST context plug-in", CreateInstance,
      GetSupportedLanguagesForTypes(), GetSupportedLanguagesForExpressions());
}

void TypeSystemMiniLLVM::Terminate() {
  PluginManager::UnregisterPlugin(CreateInstance);
}

void TypeSystemMiniLLVM::CreateLLVMContext() {
  assert(!m_context);
  m_context_owned = true;

  llvm::Triple triple(llvm::Triple::normalize(GetTargetTriple()));

  m_context = std::make_unique<MiniLLVMContext>(getDisplayName(), triple);
}

void TypeSystemMiniLLVM::Finalize() {
  assert(m_context);
  if (!m_context_owned)
    m_context.release();
}

const char *TypeSystemMiniLLVM::GetTargetTriple() {
  return m_target_triple.c_str();
}

void TypeSystemMiniLLVM::SetTargetTriple(llvm::StringRef target_triple) {
  m_target_triple = target_triple.str();
}

llvm::LLVMContext &TypeSystemMiniLLVM::getLLVMContext() const {
  assert(m_context);
  return m_context->m_llvm_context;
}

llvm::Module &TypeSystemMiniLLVM::getLLVMModule() const {
  assert(m_context);
  return m_context->m_module;
}

const MiniLLVMTargetInfo &TypeSystemMiniLLVM::getTargetInfo() const {
  assert(m_context);
  return *m_context->targetInfo;
}

namespace lldb_private {

struct MiniLLVMType {
private:
  using Payload = bool;
  llvm::PointerIntPair<llvm::Type *, 1, Payload> inner;

  bool getFlagBit() const { return inner.getInt(); }

  Payload getPayload() const { return inner.getInt(); }

  MiniLLVMType(llvm::Type *type, Payload payload) : inner(type, payload) {}

public:
  MiniLLVMType(llvm::IntegerType *type, bool is_signed)
      : inner(type, is_signed) {}

  MiniLLVMType(llvm::IntegerType *type) = delete;
  MiniLLVMType(llvm::Type *type) : inner(type, 0) {}
  MiniLLVMType(nullptr_t null) : inner(null, 0) {}

  llvm::Type *getType() const { return inner.getPointer(); }

  bool isSigned() const { return inner.getInt(); }

  bool isArrayTy() const { return getType()->isArrayTy(); }
  bool isPointerTy() const {
    return getType()->isPointerTy() ||
           getType()->getTypeID() == llvm::Type::TypedPointerTyID;
  }

  MiniLLVMType getArrayElementType() const {
    return MiniLLVMType(getType()->getArrayElementType(), getPayload());
  }

  MiniLLVMType getPointerElementType() const {
    if (getType()->getTypeID() == llvm::Type::TypedPointerTyID)
      return MiniLLVMType(
          llvm::cast<llvm::TypedPointerType>(getType())->getElementType(),
          getPayload());
    else
      return MiniLLVMType(llvm::Type::getVoidTy(getType()->getContext()));
  }

  MiniLLVMType getArrayType(uint64_t size) const {
    return MiniLLVMType(llvm::ArrayType::get(getType(), size), getPayload());
  }

  MiniLLVMType getPointerType() const {
    if (getType()->isVoidTy()) {
      return MiniLLVMType(llvm::PointerType::get(getType()->getContext(), 0));
    }
    return MiniLLVMType(llvm::TypedPointerType::get(getType(), 0),
                        getPayload());
  }

  uint64_t getArrayNumElements() const {
    return getType()->getArrayNumElements();
  }

  lldb::opaque_compiler_type_t getOpaqueType() const {
    return inner.getOpaqueValue();
  }

  static MiniLLVMType getFromOpaque(lldb::opaque_compiler_type_t opaque) {
    auto pair =
        llvm::PointerIntPair<llvm::Type *, 1, bool>::getFromOpaqueValue(opaque);
    return MiniLLVMType(pair.getPointer(), pair.getInt());
  }

  bool isFloatingPointTy() const { return getType()->isFloatingPointTy(); }

  operator bool() const { return inner.getPointer() != nullptr; }
};

} // namespace lldb_private

CompilerType TypeSystemMiniLLVM::GetType(MiniLLVMType type) {
  lldb::opaque_compiler_type_t opaque = type.getOpaqueType();
  if (!opaque)
    return CompilerType();
  return CompilerType(weak_from_this(), opaque);
}

MiniLLVMType
TypeSystemMiniLLVM::GetMiniType(lldb::opaque_compiler_type_t type) const {
  return MiniLLVMType::getFromOpaque(type);
}

#pragma mark Basic Types

CompilerType
TypeSystemMiniLLVM::GetBuiltinTypeForEncodingAndBitSize(Encoding encoding,
                                                        size_t bit_size) {
  auto &llvm = getLLVMContext();

  switch (encoding) {
  case eEncodingInvalid:
    if (bit_size == GetPointerByteSize() * 8)
      return GetType({llvm::PointerType::get(llvm, 0)});
    break;

  case eEncodingUint:
    return GetType({llvm::Type::getIntNTy(llvm, bit_size), false});
    break;

  case eEncodingSint:
    return GetType({llvm::Type::getIntNTy(llvm, bit_size), true});
    break;

  case eEncodingIEEE754:
    switch (bit_size) {
    case 16:
      return GetType({llvm::Type::getHalfTy(llvm)});
    case 32:
      return GetType({llvm::Type::getFloatTy(llvm)});
    case 64:
      return GetType({llvm::Type::getDoubleTy(llvm)});
    case 128:
      return GetType({llvm::Type::getFP128Ty(llvm)});
    }
    break;

  case eEncodingVector:
    // Sanity check that bit_size is a multiple of 8's.
    if (bit_size && !(bit_size & 0x7u))
      return GetType(
          {llvm::VectorType::get(llvm::Type::getInt8Ty(llvm),
                                 llvm::ElementCount::getFixed(bit_size / 8))});
    break;
  }

  return CompilerType();
}

uint32_t TypeSystemMiniLLVM::GetPointerByteSize() {
  if (m_pointer_byte_size == 0)
    m_pointer_byte_size = 64; // TODO: 32bit support
  return m_pointer_byte_size;
}

CompilerType TypeSystemMiniLLVM::GetTypeForDecl(void *opaque_decl) {
  return CompilerType();
}

// Tests

#ifndef NDEBUG
bool TypeSystemMiniLLVM::Verify(lldb::opaque_compiler_type_t type) {
  return !type || llvm::isa<llvm::Type>(GetMiniType(type).getType());
}
#endif

bool TypeSystemMiniLLVM::IsAggregateType(lldb::opaque_compiler_type_t type) {
  switch (GetMiniType(type).getType()->getTypeID()) {
  case llvm::Type::StructTyID:
  case llvm::Type::ArrayTyID:
  case llvm::Type::X86_AMXTyID:
  case llvm::Type::FixedVectorTyID:
  case llvm::Type::ScalableVectorTyID:
    return true;
  default:
    break;
  }
  // The type does have a value
  return false;
}

bool TypeSystemMiniLLVM::IsAnonymousType(lldb::opaque_compiler_type_t type) {
  auto *llvm_type = GetMiniType(type).getType();
  if (llvm_type->isStructTy()) {
    return llvm_type->getStructName() == "";
  }
  return false;
}

bool TypeSystemMiniLLVM::IsArrayType(lldb::opaque_compiler_type_t type,
                                     CompilerType *element_type_ptr,
                                     uint64_t *size, bool *is_incomplete) {
  auto mini_type = GetMiniType(type);

  if (mini_type.isArrayTy()) {
    if (element_type_ptr)
      element_type_ptr->SetCompilerType(
          weak_from_this(), mini_type.getArrayElementType().getOpaqueType());
    if (size)
      *size = mini_type.getArrayNumElements();
    if (is_incomplete)
      *is_incomplete = mini_type.getArrayNumElements() == 0;
    return true;
  }

  if (element_type_ptr)
    element_type_ptr->Clear();
  if (size)
    *size = 0;
  if (is_incomplete)
    *is_incomplete = false;
  return false;
}

bool TypeSystemMiniLLVM::IsVectorType(lldb::opaque_compiler_type_t type,
                                      CompilerType *element_type,
                                      uint64_t *size) {
  auto *llvm_type = GetMiniType(type).getType();

  switch (llvm_type->getTypeID()) {
  case llvm::Type::FixedVectorTyID: {
    auto *fixedVectorType = llvm::cast<llvm::FixedVectorType>(llvm_type);
    if (element_type)
      element_type->SetCompilerType(
          weak_from_this(),
          MiniLLVMType(fixedVectorType->getElementType()).getOpaqueType());
    if (size)
      *size = fixedVectorType->getNumElements();
    return true;
  } break;
  case llvm::Type::ScalableVectorTyID: {
    auto *scalableVectorType = llvm::cast<llvm::ScalableVectorType>(llvm_type);
    if (element_type)
      element_type->SetCompilerType(
          weak_from_this(),
          MiniLLVMType(scalableVectorType->getElementType()).getOpaqueType());
    if (size)
      *size = scalableVectorType->getElementCount().getKnownMinValue();
    return true;
  } break;
  default:
    break;
  }

  return false;
}

bool TypeSystemMiniLLVM::IsRuntimeGeneratedType(
    lldb::opaque_compiler_type_t type) {
  return false;
}

bool TypeSystemMiniLLVM::IsCharType(lldb::opaque_compiler_type_t type) {
  return GetMiniType(type).getType()->isIntegerTy(8);
}

bool TypeSystemMiniLLVM::IsCompleteType(lldb::opaque_compiler_type_t type) {
  return true; // TODO: no incmplete type in minillvm
}

bool TypeSystemMiniLLVM::IsConst(lldb::opaque_compiler_type_t type) {
  return false; // TODO?
}

unsigned TypeSystemMiniLLVM::GetPtrAuthKey(lldb::opaque_compiler_type_t type) {
  return 0; // TODO?
}

unsigned
TypeSystemMiniLLVM::GetPtrAuthDiscriminator(lldb::opaque_compiler_type_t type) {
  return 0; // TODO?
}

bool TypeSystemMiniLLVM::GetPtrAuthAddressDiversity(
    lldb::opaque_compiler_type_t type) {
  return 0; // TODO?
}

bool TypeSystemMiniLLVM::IsFunctionType(lldb::opaque_compiler_type_t type) {
  if (GetMiniType(type).getType()->getTypeID() == llvm::Type::FunctionTyID) {
    return true;
  }
  return false;
}

// Used to detect "Homogeneous Floating-point Aggregates"
uint32_t
TypeSystemMiniLLVM::IsHomogeneousAggregate(lldb::opaque_compiler_type_t type,
                                           CompilerType *base_type_ptr) {
  if (!type)
    return 0;

  auto mini_type = GetMiniType(type);

  switch (mini_type.getType()->getTypeID()) {
  case llvm::Type::StructTyID: {
    auto *struct_type = llvm::cast<llvm::StructType>(mini_type.getType());
    if (struct_type->isOpaque())
      return 0;

    uint32_t num_fields = struct_type->getNumElements();
    if (num_fields == 0)
      return 0;

    MiniLLVMType base_type(nullptr);
    for (uint32_t i = 0; i < num_fields; ++i) {
      auto field_type = MiniLLVMType(struct_type->getElementType(i));
      if (field_type.isFloatingPointTy()) {
        if (base_type) {
          if (base_type != field_type)
            return 0;
        } else {
          base_type = field_type;
        }
      } else {
        return 0;
      }
    }

    if (base_type_ptr)
      *base_type_ptr = GetType(base_type);
    return num_fields;
  } break;
  default:
    break;
  }

  return 0;
}

size_t TypeSystemMiniLLVM::GetNumberOfFunctionArguments(
    lldb::opaque_compiler_type_t type) {
  if (type) {
    auto *func =
        llvm::dyn_cast<llvm::FunctionType>(GetMiniType(type).getType());
    if (func)
      return func->getNumParams();
  }
  return 0;
}

CompilerType TypeSystemMiniLLVM::GetFunctionArgumentAtIndex(
    lldb::opaque_compiler_type_t type, const size_t index) {
  if (type) {
    auto *func =
        llvm::dyn_cast<llvm::FunctionType>(GetMiniType(type).getType());
    if (func) {
      if (index < func->getNumParams())
        return GetType(func->getParamType(index));
    }
  }
  return CompilerType();
}

bool TypeSystemMiniLLVM::IsMemberFunctionPointerType(
    lldb::opaque_compiler_type_t type) {
  return false;
}

bool TypeSystemMiniLLVM::IsFunctionPointerType(
    lldb::opaque_compiler_type_t type) {
  auto mini_type = GetMiniType(type);
  if (mini_type.isPointerTy()) {
    return IsFunctionType(mini_type.getPointerElementType().getOpaqueType());
  }
  return false;
}

bool TypeSystemMiniLLVM::IsBlockPointerType(
    lldb::opaque_compiler_type_t type,
    CompilerType *function_pointer_type_ptr) {
  return false; // TODO? Objc
}

bool TypeSystemMiniLLVM::IsIntegerType(lldb::opaque_compiler_type_t type,
                                       bool &is_signed) {
  if (!type)
    return false;

  auto mini_type = GetMiniType(type);
  if (mini_type.getType()->isIntegerTy()) {
    is_signed = mini_type.isSigned();
    return true;
  }

  return false;
}

bool TypeSystemMiniLLVM::IsEnumerationType(lldb::opaque_compiler_type_t type,
                                           bool &is_signed) {
  return false; // TODO? minillvm doesn't have enum
}

bool TypeSystemMiniLLVM::IsScopedEnumerationType(
    lldb::opaque_compiler_type_t type) {
  return false; // TODO? minillvm doesn't have enum
}

bool TypeSystemMiniLLVM::IsPointerType(lldb::opaque_compiler_type_t type,
                                       CompilerType *pointee_type) {
  if (type) {
    auto mini_type = GetMiniType(type);
    if (mini_type.isPointerTy()) {
      if (pointee_type)
        pointee_type->SetCompilerType(
            weak_from_this(),
            mini_type.getPointerElementType().getOpaqueType());
      return true;
    }
  }
  if (pointee_type)
    pointee_type->Clear();
  return false;
}

bool TypeSystemMiniLLVM::IsPointerOrReferenceType(
    lldb::opaque_compiler_type_t type, CompilerType *pointee_type) {
  return IsPointerType(type, pointee_type);
}

bool TypeSystemMiniLLVM::IsReferenceType(lldb::opaque_compiler_type_t type,
                                         CompilerType *pointee_type,
                                         bool *is_rvalue) {
  return false; // TODO: minillvm reference type? (C++)
}

bool TypeSystemMiniLLVM::IsFloatingPointType(lldb::opaque_compiler_type_t type,
                                             uint32_t &count,
                                             bool &is_complex) {
  if (type) {
    auto *llvm_type = GetMiniType(type).getType();
    switch (llvm_type->getTypeID()) {
    case llvm::Type::HalfTyID:
    case llvm::Type::BFloatTyID:
    case llvm::Type::FloatTyID:
    case llvm::Type::DoubleTyID:
    case llvm::Type::X86_FP80TyID:
    case llvm::Type::FP128TyID:
    case llvm::Type::PPC_FP128TyID:
      count = 1;
      is_complex = false;
      return true;
    case llvm::Type::FixedVectorTyID: {
      auto *fixedVectorType = llvm::cast<llvm::FixedVectorType>(llvm_type);
      if (IsFloatingPointType(
              MiniLLVMType(fixedVectorType->getElementType()).getOpaqueType(),
              count, is_complex)) {
        count = fixedVectorType->getNumElements();
        is_complex = false;
        return true;
      }
    } break;
    default:
      break;
    }
  }
  count = 0;
  is_complex = false;
  return false;
}

bool TypeSystemMiniLLVM::IsDefined(lldb::opaque_compiler_type_t type) {
  if (!type)
    return false;
  // TODO: what's undefined types in minillvm?
  return true;
}

bool TypeSystemMiniLLVM::IsPolymorphicClass(lldb::opaque_compiler_type_t type) {
  return false; // TODO: C++ support?
}

bool TypeSystemMiniLLVM::IsPossibleDynamicType(
    lldb::opaque_compiler_type_t type, CompilerType *dynamic_pointee_type,
    bool check_cplusplus, bool check_objc) {
  MiniLLVMType pointee_mini_type(nullptr);
  if (type) {
    auto mini_type = GetMiniType(type);
    bool success = false;

    switch (mini_type.getType()->getTypeID()) {
    case llvm::Type::PointerTyID:
    case llvm::Type::TypedPointerTyID:
      pointee_mini_type = mini_type.getPointerElementType();
      success = true;
      break;
    default:
      break;
    }

    if (success) {
      // Check to make sure what we are pointing too is a possible dynamic C++
      // type We currently accept any "void *" (in case we have a class that
      // has been watered down to an opaque pointer) and virtual C++ classes.
      switch (pointee_mini_type.getType()->getTypeID()) {
      case llvm::Type::VoidTyID:
        if (dynamic_pointee_type)
          dynamic_pointee_type->SetCompilerType(
              weak_from_this(), pointee_mini_type.getOpaqueType());
        return true;
      default:
        break;
      }
    }
  }
  if (dynamic_pointee_type)
    dynamic_pointee_type->Clear();
  return false;
}

bool TypeSystemMiniLLVM::IsScalarType(lldb::opaque_compiler_type_t type) {
  if (!type)
    return false;

  return (GetTypeInfo(type, nullptr) & eTypeIsScalar) != 0;
}

bool TypeSystemMiniLLVM::IsTypedefType(lldb::opaque_compiler_type_t type) {
  return false; // TODO: no typedef in minillvm
}

bool TypeSystemMiniLLVM::IsVoidType(lldb::opaque_compiler_type_t type) {
  if (!type)
    return false;
  return GetMiniType(type).getType()->isVoidTy();
}

bool TypeSystemMiniLLVM::CanPassInRegisters(const CompilerType &type) {
  // Pass by Register types are integer or pointer type on the llvm level
  // TODO: implement when extend
  return false;
}

bool TypeSystemMiniLLVM::SupportsLanguage(lldb::LanguageType language) {
  return TypeSystemMiniLLVMSupportsLanguage(language);
}

bool TypeSystemMiniLLVM::IsBeingDefined(lldb::opaque_compiler_type_t type) {
  return false; // TODO: IDK what this means
}

// Type Completion

bool TypeSystemMiniLLVM::GetCompleteType(lldb::opaque_compiler_type_t type) {
  if (!type)
    return false;
  return true; // TODO: IDK what this means
}

ConstString TypeSystemMiniLLVM::GetTypeName(lldb::opaque_compiler_type_t type,
                                            bool base_only) {
  if (!type)
    return ConstString();

  MiniLLVMType mini_type = GetMiniType(type);

  switch (mini_type.getType()->getTypeID()) {
  case llvm::Type::HalfTyID:
    return ConstString("half");
  case llvm::Type::BFloatTyID:
    return ConstString("bfloat");
  case llvm::Type::FloatTyID:
    return ConstString("float");
  case llvm::Type::DoubleTyID:
    return ConstString("double");
  case llvm::Type::X86_FP80TyID:
    return ConstString("x86_fp80");
  case llvm::Type::FP128TyID:
    return ConstString("fp128");
  case llvm::Type::PPC_FP128TyID:
    return ConstString("ppc_fp128");
  case llvm::Type::VoidTyID:
    return ConstString("void");
  case llvm::Type::LabelTyID:
    return ConstString("label");
  case llvm::Type::MetadataTyID:
    return ConstString("metadata");
  case llvm::Type::X86_AMXTyID:
    return ConstString("x86_amx");
  case llvm::Type::TokenTyID:
    return ConstString("token");
  case llvm::Type::PointerTyID:
    return ConstString("ptr");
  case llvm::Type::IntegerTyID: {
    unsigned bit_width = mini_type.getType()->getIntegerBitWidth();

    llvm::SmallVector<char, 1024> buf;
    llvm::raw_svector_ostream name_stream(buf);

    name_stream << (mini_type.isSigned() ? "i" : "u") << bit_width;

    return ConstString(name_stream.str());
  }
  case llvm::Type::FunctionTyID: {
    auto *func = llvm::cast<llvm::FunctionType>(mini_type.getType());

    llvm::SmallVector<char, 1024> buf;
    llvm::raw_svector_ostream name_stream(buf);

    name_stream << GetTypeName(
                       GetType({func->getReturnType()}).GetOpaqueQualType(),
                       base_only)
                << " (";

    for (unsigned i = 0, e = func->getNumParams(); i != e; ++i) {
      if (i)
        name_stream << ", ";
      name_stream << GetTypeName(
          GetType({func->getParamType(i)}).GetOpaqueQualType(), base_only);
    }

    if (func->isVarArg()) {
      if (func->getNumParams() > 0)
        name_stream << ", ";
      name_stream << "...";
    }

    name_stream << ")";

    return ConstString(name_stream.str());
  }
  case llvm::Type::StructTyID: {
    return ConstString(mini_type.getType()->getStructName());
  }
  case llvm::Type::ArrayTyID: {
    auto *arrayType = llvm::cast<llvm::ArrayType>(mini_type.getType());

    llvm::SmallVector<char, 1024> buf;
    llvm::raw_svector_ostream name_stream(buf);

    name_stream << "[" << arrayType->getNumElements() << "x"
                << GetTypeName(GetType({arrayType->getElementType()})
                                   .GetOpaqueQualType(),
                               base_only)
                << "]";

    return ConstString(name_stream.str());
  }
  case llvm::Type::FixedVectorTyID:
  case llvm::Type::ScalableVectorTyID: {
    auto *fixedVectorType = llvm::cast<llvm::VectorType>(mini_type.getType());
    auto count = fixedVectorType->getElementCount();

    llvm::SmallVector<char, 1024> buf;
    llvm::raw_svector_ostream name_stream(buf);

    name_stream << "<";
    if (count.isScalable()) {
      name_stream << "vscale x";
    }
    name_stream << count.getKnownMinValue() << " x "
                << GetTypeName(GetType({fixedVectorType->getElementType()})
                                   .GetOpaqueQualType(),
                               base_only)
                << ">";
    return ConstString(name_stream.str());
  }
  case llvm::Type::TypedPointerTyID: {
    auto *typedPointerType =
        llvm::cast<llvm::TypedPointerType>(mini_type.getType());

    llvm::SmallVector<char, 1024> buf;
    llvm::raw_svector_ostream name_stream(buf);

    name_stream << GetTypeName(GetType({typedPointerType->getElementType()})
                                   .GetOpaqueQualType(),
                               base_only)
                << "*";

    return ConstString(name_stream.str());
  }
  case llvm::Type::TargetExtTyID: {
    return ConstString(mini_type.getType()->getTargetExtName());
  }
  }

  return ConstString();
}

ConstString
TypeSystemMiniLLVM::GetDisplayTypeName(lldb::opaque_compiler_type_t type) {
  if (!type)
    return ConstString();
  return GetTypeName(type, true);
}

uint32_t TypeSystemMiniLLVM::GetTypeInfo(lldb::opaque_compiler_type_t type,
                                         CompilerType *pointee_or_type) {
  if (!type)
    return 0;

  if (pointee_or_type)
    pointee_or_type->Clear();

  auto mini_type = GetMiniType(type);

  switch (mini_type.getType()->getTypeID()) {
  case llvm::Type::IntegerTyID: {
    uint32_t builtin_type_flags = eTypeIsBuiltIn | eTypeHasValue;
    builtin_type_flags |= eTypeIsScalar;
    if (mini_type.getType()->getIntegerBitWidth() != 1) { // 1 is bool
      builtin_type_flags |= eTypeIsInteger;
      if (mini_type.isSigned())
        builtin_type_flags |= eTypeIsSigned;
    }
    return builtin_type_flags;
  }
  case llvm::Type::FloatTyID: {
    uint32_t builtin_type_flags = eTypeIsBuiltIn | eTypeHasValue;
    builtin_type_flags |= eTypeIsScalar;
    builtin_type_flags |= eTypeIsFloat;
    return builtin_type_flags;
  }
  case llvm::Type::ArrayTyID: {
    if (pointee_or_type)
      pointee_or_type->SetCompilerType(
          weak_from_this(), mini_type.getArrayElementType().getOpaqueType());
    return eTypeHasChildren | eTypeIsArray;
  }
  case llvm::Type::FunctionTyID: {
    return eTypeIsFuncPrototype | eTypeHasValue;
  }
  case llvm::Type::PointerTyID:
  case llvm::Type::TypedPointerTyID: {
    if (pointee_or_type)
      pointee_or_type->SetCompilerType(
          weak_from_this(), mini_type.getPointerElementType().getOpaqueType());
    return eTypeHasChildren | eTypeIsPointer | eTypeHasValue;
  }
  case llvm::Type::StructTyID: {
    return eTypeHasChildren | eTypeIsStructUnion;
  }
  case llvm::Type::FixedVectorTyID:
  case llvm::Type::ScalableVectorTyID: {
    return eTypeHasChildren | eTypeIsVector;
  }
  default:
    return 0;
  }
  return 0;
}

lldb::LanguageType
TypeSystemMiniLLVM::GetMinimumLanguage(lldb::opaque_compiler_type_t type) {
  return lldb::eLanguageTypeMiniLLVM;
}

lldb::TypeClass
TypeSystemMiniLLVM::GetTypeClass(lldb::opaque_compiler_type_t type) {
  if (!type)
    return lldb::eTypeClassInvalid;

  auto *llvm_type = GetMiniType(type).getType();
  switch (llvm_type->getTypeID()) {
  case llvm::Type::HalfTyID:
  case llvm::Type::BFloatTyID:
  case llvm::Type::FloatTyID:
  case llvm::Type::DoubleTyID:
  case llvm::Type::X86_FP80TyID:
  case llvm::Type::FP128TyID:
  case llvm::Type::PPC_FP128TyID:
  case llvm::Type::IntegerTyID:
    return lldb::eTypeClassBuiltin;
  case llvm::Type::FunctionTyID:
    return lldb::eTypeClassFunction;
  case llvm::Type::ArrayTyID:
    return lldb::eTypeClassArray;
  case llvm::Type::PointerTyID:
  case llvm::Type::TypedPointerTyID:
    return lldb::eTypeClassPointer;
  case llvm::Type::StructTyID:
    return lldb::eTypeClassStruct;
  case llvm::Type::FixedVectorTyID:
  case llvm::Type::ScalableVectorTyID:
    return lldb::eTypeClassVector;
  // We don't know hot to display this type...
  case llvm::Type::LabelTyID:
  case llvm::Type::MetadataTyID:
  case llvm::Type::X86_AMXTyID:
  case llvm::Type::TokenTyID:
  case llvm::Type::TargetExtTyID:
  default:
    return lldb::eTypeClassOther;
  }
}

unsigned
TypeSystemMiniLLVM::GetTypeQualifiers(lldb::opaque_compiler_type_t type) {
  return 0; // TODO: Clang dependant
}

// Creating related types

CompilerType
TypeSystemMiniLLVM::GetArrayElementType(lldb::opaque_compiler_type_t type,
                                        ExecutionContextScope *exe_scope) {
  if (type) {
    auto mini_type = GetMiniType(type);

    if (mini_type.isArrayTy()) {
      return GetType({mini_type.getArrayElementType()});
    }
  }
  return CompilerType();
}

CompilerType TypeSystemMiniLLVM::GetArrayType(lldb::opaque_compiler_type_t type,
                                              uint64_t size) {
  if (type) {
    return GetType(GetMiniType(type).getArrayType(size));
  }

  return CompilerType();
}

CompilerType
TypeSystemMiniLLVM::GetCanonicalType(lldb::opaque_compiler_type_t type) {
  if (type)
    return GetType(GetMiniType(type));
  return CompilerType();
}

CompilerType
TypeSystemMiniLLVM::GetFullyUnqualifiedType(lldb::opaque_compiler_type_t type) {
  if (type)
    return GetType(GetMiniType(type));
  return CompilerType();
}

CompilerType TypeSystemMiniLLVM::GetEnumerationIntegerType(
    lldb::opaque_compiler_type_t type) {
  return CompilerType(); // TODO: no enum in minillvm
}

int TypeSystemMiniLLVM::GetFunctionArgumentCount(
    lldb::opaque_compiler_type_t type) {
  if (type) {
    auto *llvm_type = GetMiniType(type).getType();
    if (llvm_type->isFunctionTy()) {
      return llvm_type->getFunctionNumParams();
    }
  }
  return -1;
}

CompilerType TypeSystemMiniLLVM::GetFunctionArgumentTypeAtIndex(
    lldb::opaque_compiler_type_t type, size_t idx) {
  if (type) {
    auto *llvm_type = GetMiniType(type).getType();
    if (llvm_type->isFunctionTy()) {
      return GetType({llvm_type->getFunctionParamType(idx)});
    }
  }
  return CompilerType();
}

CompilerType
TypeSystemMiniLLVM::GetFunctionReturnType(lldb::opaque_compiler_type_t type) {
  if (type) {
    auto *llvm_type = GetMiniType(type).getType();
    if (llvm_type->isFunctionTy()) {
      return GetType({llvm::cast<llvm::FunctionType>(llvm_type)->getReturnType()});
    }
  }
  return CompilerType();
}

size_t
TypeSystemMiniLLVM::GetNumMemberFunctions(lldb::opaque_compiler_type_t type) {
  return 0; // no c++ support
}

TypeMemberFunctionImpl
TypeSystemMiniLLVM::GetMemberFunctionAtIndex(lldb::opaque_compiler_type_t type,
                                             size_t idx) {
  return TypeMemberFunctionImpl();
}

CompilerType
TypeSystemMiniLLVM::GetNonReferenceType(lldb::opaque_compiler_type_t type) {
  return CompilerType(); // no reference in minillvm
}

CompilerType
TypeSystemMiniLLVM::GetPointeeType(lldb::opaque_compiler_type_t type) {
  if (type)
    return GetType(GetMiniType(type).getPointerElementType());
  return CompilerType();
}

CompilerType
TypeSystemMiniLLVM::GetPointerType(lldb::opaque_compiler_type_t type) {
  if (type) {
    return GetType(GetMiniType(type).getPointerType());
  }
  return CompilerType();
}

CompilerType
TypeSystemMiniLLVM::GetLValueReferenceType(lldb::opaque_compiler_type_t type) {
  return CompilerType(); // no c++ support
}

CompilerType
TypeSystemMiniLLVM::GetRValueReferenceType(lldb::opaque_compiler_type_t type) {
  return CompilerType(); // no c++ support
}

CompilerType
TypeSystemMiniLLVM::GetAtomicType(lldb::opaque_compiler_type_t type) {
  return CompilerType(); // no atomic type in minillvm
}

CompilerType
TypeSystemMiniLLVM::AddConstModifier(lldb::opaque_compiler_type_t type) {
  if (type) {
    return GetType(GetMiniType(type)); // No Const in minillvm
  }
  return CompilerType();
}

CompilerType
TypeSystemMiniLLVM::AddPtrAuthModifier(lldb::opaque_compiler_type_t type,
                                       uint32_t payload) {
  return CompilerType(); // no ptr auth in minillvm
}

CompilerType
TypeSystemMiniLLVM::AddVolatileModifier(lldb::opaque_compiler_type_t type) {
  return CompilerType(); // no volatile auth in minillvm
}

CompilerType
TypeSystemMiniLLVM::AddRestrictModifier(lldb::opaque_compiler_type_t type) {
  return CompilerType(); // no restrict auth in minillvm
}

CompilerType TypeSystemMiniLLVM::CreateTypedef(
    lldb::opaque_compiler_type_t type, const char *typedef_name,
    const CompilerDeclContext &compiler_decl_ctx, uint32_t payload) {
  return CompilerType(); // TODO: no typedef in minillvm
}

CompilerType
TypeSystemMiniLLVM::GetTypedefedType(lldb::opaque_compiler_type_t type) {
  return CompilerType(); // TODO: no typedef in minillvm
}

// Create related types using the current type's AST

CompilerType
TypeSystemMiniLLVM::GetBasicTypeFromAST(lldb::BasicType basic_type) {
  switch (basic_type) {
  case eBasicTypeVoid:
    return GetType({llvm::Type::getVoidTy(getLLVMContext())});
  case eBasicTypeChar:
    return GetType({llvm::Type::getInt8Ty(getLLVMContext()), true});
  case eBasicTypeSignedChar:
    return GetType({llvm::Type::getInt8Ty(getLLVMContext()), true});
  case eBasicTypeUnsignedChar:
    return GetType({llvm::Type::getInt8Ty(getLLVMContext()), false});
  case eBasicTypeWChar:
    switch (getTargetInfo().wcharType) {
    case WCharType::SignedInt32:
      return GetType({llvm::Type::getInt32Ty(getLLVMContext()), true});
    case WCharType::UnsignedInt16:
      return GetType({llvm::Type::getInt16Ty(getLLVMContext()), false});
      break;
    }
    break;
  case eBasicTypeSignedWChar:
    return GetType({llvm::Type::getInt16Ty(getLLVMContext()), true});
  case eBasicTypeUnsignedWChar:
    return GetType({llvm::Type::getInt16Ty(getLLVMContext()), false});
  case eBasicTypeChar16:
    return GetType({llvm::Type::getInt16Ty(getLLVMContext()), false});
  case eBasicTypeChar32:
    return GetType({llvm::Type::getInt32Ty(getLLVMContext()), false});
  case eBasicTypeChar8:
    return GetType({llvm::Type::getInt8Ty(getLLVMContext()), false});
  case eBasicTypeShort:
    return GetType({llvm::Type::getInt16Ty(getLLVMContext()), true});
  case eBasicTypeUnsignedShort:
    return GetType({llvm::Type::getInt16Ty(getLLVMContext()), false});
  case eBasicTypeInt:
    return GetType(
        {llvm::Type::getIntNTy(getLLVMContext(), getTargetInfo().intWidth), true});
  case eBasicTypeUnsignedInt:
    return GetType(
        {llvm::Type::getIntNTy(getLLVMContext(), getTargetInfo().intWidth), false});
  case eBasicTypeLong:
    return GetType(
        {llvm::Type::getIntNTy(getLLVMContext(), getTargetInfo().longWidth), false});
  case eBasicTypeUnsignedLong:
    return GetType(
        {llvm::Type::getIntNTy(getLLVMContext(), getTargetInfo().longWidth), false});
  case eBasicTypeLongLong:
    return GetType({llvm::Type::getIntNTy(getLLVMContext(), getTargetInfo().longLongWidth), true});
  case eBasicTypeUnsignedLongLong:
    return GetType({llvm::Type::getIntNTy(getLLVMContext(), getTargetInfo().longLongWidth), false});
  case eBasicTypeInt128:
    return GetType({llvm::Type::getInt128Ty(getLLVMContext()), true});
  case eBasicTypeUnsignedInt128:
    return GetType({llvm::Type::getInt128Ty(getLLVMContext()), false});
  case eBasicTypeBool:
    return GetType({llvm::Type::getInt1Ty(getLLVMContext()), false});
  case eBasicTypeHalf:
    return GetType({llvm::Type::getHalfTy(getLLVMContext())});
  case eBasicTypeFloat:
    return GetType({llvm::Type::getFloatTy(getLLVMContext())});
  case eBasicTypeDouble:
    return GetType({llvm::Type::getDoubleTy(getLLVMContext())});
  case eBasicTypeLongDouble:
    switch (getTargetInfo().longDoubleType) {
    case LongDoubleType::Float64:
      return GetType({llvm::Type::getDoubleTy(getLLVMContext())});
    case LongDoubleType::Float80:
      return GetType({llvm::Type::getX86_FP80Ty(getLLVMContext())});
    case LongDoubleType::Float128:
      return GetType({llvm::Type::getFP128Ty(getLLVMContext())});
    case LongDoubleType::DoubleDouble:
      return GetType({llvm::Type::getPPC_FP128Ty(getLLVMContext())});
    }
    break;
  case eBasicTypeNullPtr:
    return GetType({llvm::PointerType::get(getLLVMContext(), 0)});
  default:
    break;
  }
  return CompilerType();
}

CompilerType TypeSystemMiniLLVM::CreateGenericFunctionPrototype() {
  return CompilerType(); // TODO: unsupported
}
// Exploring the type

const llvm::fltSemantics &
TypeSystemMiniLLVM::GetFloatTypeSemantics(size_t byte_size) {
  const size_t bit_size = byte_size * 8;
  if (bit_size == 32)
    return llvm::APFloatBase::IEEEsingle();
  else if (bit_size == 64)
    return llvm::APFloatBase::IEEEdouble();
  else if (bit_size == 16)
    return llvm::APFloatBase::IEEEhalf();

  if (bit_size == (size_t)getTargetInfo().longDoubleWidth) {
    switch (getTargetInfo().longDoubleType) {
    case LongDoubleType::Float64:
      return llvm::APFloatBase::IEEEdouble();
    case LongDoubleType::Float80:
      return llvm::APFloatBase::x87DoubleExtended();
    case LongDoubleType::Float128:
      return llvm::APFloatBase::IEEEquad();
    case LongDoubleType::DoubleDouble:
      return llvm::APFloatBase::PPCDoubleDouble();
    }
  }
  return llvm::APFloatBase::Bogus();
}

std::optional<uint64_t>
TypeSystemMiniLLVM::GetBitSize(lldb::opaque_compiler_type_t type,
                               ExecutionContextScope *exe_scope) {
  return getLLVMModule().getDataLayout().getTypeAllocSize(
      GetMiniType(type).getType());
}

std::optional<size_t>
TypeSystemMiniLLVM::GetTypeBitAlign(lldb::opaque_compiler_type_t type,
                                    ExecutionContextScope *exe_scope) {
  return (size_t)getLLVMModule()
      .getDataLayout()
      .getABITypeAlign(GetMiniType(type).getType())
      .value();
}

lldb::Encoding
TypeSystemMiniLLVM::GetEncoding(lldb::opaque_compiler_type_t type,
                                uint64_t &count) {
  if (!type)
    return lldb::eEncodingInvalid;

  auto mini_type = GetMiniType(type);

  switch (mini_type.getType()->getTypeID()) {
  case llvm::Type::HalfTyID:
  case llvm::Type::BFloatTyID:
  case llvm::Type::FloatTyID:
  case llvm::Type::DoubleTyID:
  case llvm::Type::X86_FP80TyID:
  case llvm::Type::FP128TyID:
  case llvm::Type::PPC_FP128TyID:
    return lldb::eEncodingIEEE754;
    ;

  case llvm::Type::IntegerTyID:
    return mini_type.isSigned() ? lldb::eEncodingSint : lldb::eEncodingUint;

  // pointer types
  case llvm::Type::FunctionTyID:
  case llvm::Type::PointerTyID:
    return lldb::eEncodingUint;

  default:
    return lldb::eEncodingInvalid;
  }
}

lldb::Format TypeSystemMiniLLVM::GetFormat(lldb::opaque_compiler_type_t type) {
  if (!type)
    return lldb::eFormatDefault;

  auto mini_type = GetMiniType(type);

  switch (mini_type.getType()->getTypeID()) {
  case llvm::Type::IntegerTyID:
    if (mini_type.getType()->getIntegerBitWidth() == 1)
      return eFormatBoolean;
    else if (mini_type.isSigned())
      return eFormatDecimal;
    else
      return eFormatUnsigned;

  case llvm::Type::HalfTyID:
  case llvm::Type::BFloatTyID:
  case llvm::Type::FloatTyID:
  case llvm::Type::DoubleTyID:
  case llvm::Type::X86_FP80TyID:
  case llvm::Type::FP128TyID:
  case llvm::Type::PPC_FP128TyID:
    return lldb::eFormatFloat;

  case llvm::Type::PointerTyID:
  case llvm::Type::TypedPointerTyID:
  case llvm::Type::FunctionTyID:
    return lldb::eFormatHex;
  case llvm::Type::ArrayTyID:
    return lldb::eFormatHex;
  case llvm::Type::StructTyID:
    break;

  case llvm::Type::FixedVectorTyID:
  case llvm::Type::ScalableVectorTyID:
    break;
  case llvm::Type::LabelTyID:
  case llvm::Type::MetadataTyID:
  case llvm::Type::X86_AMXTyID:
  case llvm::Type::TokenTyID:
  case llvm::Type::TargetExtTyID:
  default:
    break;
  }

  // We don't know hot to display this type...
  return lldb::eFormatBytes;
}

llvm::Expected<uint32_t>
TypeSystemMiniLLVM::GetNumChildren(lldb::opaque_compiler_type_t type,
                                   bool omit_empty_base_classes,
                                   const ExecutionContext *exe_ctx) {
  if (!type)
    return llvm::createStringError("invalid type");

  uint32_t num_children = 0;
  auto mini_type = GetMiniType(type);

  switch (mini_type.getType()->getTypeID()) {
  case llvm::Type::IntegerTyID:
  case llvm::Type::HalfTyID:
  case llvm::Type::BFloatTyID:
  case llvm::Type::FloatTyID:
  case llvm::Type::DoubleTyID:
  case llvm::Type::X86_FP80TyID:
  case llvm::Type::FP128TyID:
  case llvm::Type::PPC_FP128TyID:
    break;
  case llvm::Type::StructTyID: {
    auto *struct_type = llvm::cast<llvm::StructType>(mini_type.getType());
    if (struct_type->isOpaque())
      return llvm::createStringError("opaque struct type");

    num_children += struct_type->getNumElements();
  } break;
  case llvm::Type::FixedVectorTyID:
  case llvm::Type::ScalableVectorTyID:
    num_children = llvm::cast<llvm::VectorType>(mini_type.getType())
                       ->getElementCount()
                       .getKnownMinValue();
    break;
  case llvm::Type::ArrayTyID:
    num_children = mini_type.getArrayNumElements();
    break;
  case llvm::Type::PointerTyID:
  case llvm::Type::TypedPointerTyID: {
    auto pointee = mini_type.getPointerElementType();
    num_children = 0;
    if (pointee.getType()->isStructTy()) {
      num_children =
          llvm::cast<llvm::StructType>(pointee.getType())->getNumElements();
    }
    if (num_children == 0) {
      num_children = pointee.getType()->isIntegerTy() ? 1 : 0;
    }
    break;
  }
  default:
    break;
  }

  return num_children;
}

CompilerType TypeSystemMiniLLVM::GetBuiltinTypeByName(ConstString name) {
  return CompilerType(); // TODO: minillvm type name
}

lldb::BasicType
TypeSystemMiniLLVM::GetBasicTypeEnumeration(lldb::opaque_compiler_type_t type) {
  if (type) {
    auto mini_type = GetMiniType(type);

    switch (mini_type.getType()->getTypeID()) {
    case llvm::Type::HalfTyID:
      return eBasicTypeHalf;
    case llvm::Type::FloatTyID:
      return eBasicTypeFloat;
    case llvm::Type::DoubleTyID:
      return eBasicTypeDouble;
    case llvm::Type::X86_FP80TyID:
      return eBasicTypeLongDouble;
    case llvm::Type::FP128TyID:
      return eBasicTypeLongDouble;
    case llvm::Type::PPC_FP128TyID:
      return eBasicTypeLongDouble;
    case llvm::Type::IntegerTyID:
      switch (mini_type.getType()->getIntegerBitWidth()) {
      case 1:
        return eBasicTypeBool;
      case 8:
        return mini_type.isSigned() ? eBasicTypeSignedChar
                                    : eBasicTypeUnsignedChar;
      case 16:
        return eBasicTypeShort;
      case 32:
        if (getTargetInfo().intWidth == 32)
          return mini_type.isSigned() ? eBasicTypeInt : eBasicTypeUnsignedInt;
        return eBasicTypeOther;
      case 64:
        if (getTargetInfo().longWidth == 64)
          return mini_type.isSigned() ? eBasicTypeLong : eBasicTypeUnsignedLong;
        else if (getTargetInfo().longLongWidth == 64)
          return mini_type.isSigned() ? eBasicTypeLongLong
                                      : eBasicTypeUnsignedLongLong;
      }
      break;
    case llvm::Type::VoidTyID:
      return eBasicTypeVoid;
    case llvm::Type::PointerTyID:
      return eBasicTypeOther;
    default:
      break;
    }
  }
  return eBasicTypeInvalid;
}

void TypeSystemMiniLLVM::ForEachEnumerator(
    lldb::opaque_compiler_type_t type,
    std::function<bool(const CompilerType &integer_type, ConstString name,
                       const llvm::APSInt &value)> const &callback) {
  // TODO: no enum in minillvm
}

#pragma mark Aggregate Types

uint32_t TypeSystemMiniLLVM::GetNumFields(lldb::opaque_compiler_type_t type) {
  if (!type)
    return 0;

  auto mini_type = GetMiniType(type);
  if (mini_type.getType()->isStructTy()) {
    return mini_type.getType()->getStructNumElements();
  }

  return 0;
}

CompilerType TypeSystemMiniLLVM::GetFieldAtIndex(
    lldb::opaque_compiler_type_t type, size_t idx, std::string &name,
    uint64_t *bit_offset_ptr, uint32_t *bitfield_bit_size_ptr,
    bool *is_bitfield_ptr) {
  if (!type)
    return CompilerType();

  auto mini_type = GetMiniType(type);
  if (mini_type.getType()->isStructTy()) {
    auto *field_type = mini_type.getType()->getStructElementType(idx);

    if (bit_offset_ptr) {
      auto *layout = getLLVMModule().getDataLayout().getStructLayout(
          llvm::cast<llvm::StructType>(mini_type.getType()));
      *bit_offset_ptr = layout->getElementOffsetInBits(idx);
    }

    if (bitfield_bit_size_ptr) {
      *bitfield_bit_size_ptr = 0;
    }
    if (is_bitfield_ptr) {
      *is_bitfield_ptr = false;
    }

    name.assign("");

    return GetType({field_type});
  }

  return CompilerType();
}

uint32_t
TypeSystemMiniLLVM::GetNumDirectBaseClasses(lldb::opaque_compiler_type_t type) {
  return 0; // no c++ support
}

uint32_t TypeSystemMiniLLVM::GetNumVirtualBaseClasses(
    lldb::opaque_compiler_type_t type) {
  return 0; // no c++ support
}

CompilerType TypeSystemMiniLLVM::GetDirectBaseClassAtIndex(
    lldb::opaque_compiler_type_t type, size_t idx, uint32_t *bit_offset_ptr) {
  return CompilerType(); // no c++ support
}

CompilerType TypeSystemMiniLLVM::GetVirtualBaseClassAtIndex(
    lldb::opaque_compiler_type_t type, size_t idx, uint32_t *bit_offset_ptr) {
  return CompilerType(); // no c++ support
}

CompilerDecl
TypeSystemMiniLLVM::GetStaticFieldWithName(lldb::opaque_compiler_type_t type,
                                           llvm::StringRef name) {
  return CompilerDecl(); // TODO: no c++ support?
}

llvm::Expected<CompilerType> TypeSystemMiniLLVM::GetChildCompilerTypeAtIndex(
    lldb::opaque_compiler_type_t type, ExecutionContext *exe_ctx, size_t idx,
    bool transparent_pointers, bool omit_empty_base_classes,
    bool ignore_array_bounds, std::string &child_name,
    uint32_t &child_byte_size, int32_t &child_byte_offset,
    uint32_t &child_bitfield_bit_size, uint32_t &child_bitfield_bit_offset,
    bool &child_is_base_class, bool &child_is_deref_of_parent,
    ValueObject *valobj, uint64_t &language_flags) {
  if (!type)
    return CompilerType();

  auto get_exe_scope = [&exe_ctx]() {
    return exe_ctx ? exe_ctx->GetBestExecutionContextScope() : nullptr;
  };

  auto mini_type = GetMiniType(type);
  child_bitfield_bit_size = 0;
  child_bitfield_bit_offset = 0;
  child_is_base_class = false;
  language_flags = 0;

  auto num_children_or_err =
      GetNumChildren(type, omit_empty_base_classes, exe_ctx);
  if (!num_children_or_err)
    return num_children_or_err.takeError();

  const bool idx_is_valid = idx < *num_children_or_err;
  int32_t bit_offset;

  switch (mini_type.getType()->getTypeID()) {
  case llvm::Type::StructTyID:
    if (idx_is_valid) {
      auto *struct_type = llvm::cast<llvm::StructType>(mini_type.getType());
      auto *layout =
          getLLVMModule().getDataLayout().getStructLayout(struct_type);
      auto *element_type = struct_type->getElementType(idx);

      child_name.assign("");
      bit_offset = layout->getElementOffsetInBits(idx);
      child_byte_offset = bit_offset / 8;
      child_byte_size =
          getLLVMModule().getDataLayout().getTypeAllocSize(element_type);

      return GetType({element_type});
    }
    break;
  case llvm::Type::FixedVectorTyID:
  case llvm::Type::ScalableVectorTyID:
    if (idx_is_valid) {
      auto *vector_type = llvm::cast<llvm::VectorType>(mini_type.getType());
      auto *element_type = vector_type->getElementType();
      child_name = std::string(llvm::formatv("[{0}]", idx));
      child_byte_size =
          getLLVMModule().getDataLayout().getTypeAllocSize(element_type);
      child_byte_offset = child_byte_size * idx;
      return GetType({element_type});
    }
    break;
  case llvm::Type::ArrayTyID:
    if (ignore_array_bounds || idx_is_valid) {
      auto *array_type = llvm::cast<llvm::ArrayType>(mini_type.getType());
      auto *element_type = array_type->getElementType();
      child_name = std::string(llvm::formatv("[{0}]", idx));
      child_byte_size =
          getLLVMModule().getDataLayout().getTypeAllocSize(element_type);
      child_byte_offset = child_byte_size * idx;
      return GetType({element_type});
    }
    break;
  case llvm::Type::PointerTyID:
  case llvm::Type::TypedPointerTyID: {
    auto pointee = GetPointeeType(type);

    // Don't dereference "void *" pointers
    if (pointee.IsVoidType())
      return CompilerType();

    if (transparent_pointers && pointee.IsAggregateType()) {
      child_is_deref_of_parent = false;
      bool tmp_child_is_deref_of_parent = false;
      return pointee.GetChildCompilerTypeAtIndex(
          exe_ctx, idx, transparent_pointers, omit_empty_base_classes,
          ignore_array_bounds, child_name, child_byte_size, child_byte_offset,
          child_bitfield_bit_size, child_bitfield_bit_offset,
          child_is_base_class, tmp_child_is_deref_of_parent, valobj,
          language_flags);
    } else {
      child_is_deref_of_parent = true;

      const char *parent_name =
          valobj ? valobj->GetName().GetCString() : nullptr;
      if (parent_name) {
        child_name.assign(1, '*');
        child_name += parent_name;
      }

      // We have a pointer to an simple type
      if (idx == 0) {
        if (std::optional<uint64_t> size =
                pointee.GetByteSize(get_exe_scope())) {
          child_byte_size = *size;
          child_byte_offset = 0;
          return pointee;
        }
      }
    }
  } break;

  default:
    break;
  }
  return CompilerType();
}

size_t TypeSystemMiniLLVM::GetIndexOfChildMemberWithName(
    lldb::opaque_compiler_type_t type, llvm::StringRef name,
    bool omit_empty_base_classes, std::vector<uint32_t> &child_indexes) {
  return 0; // minillvm everything is unnamed; we cannot accesss by name
}

uint32_t
TypeSystemMiniLLVM::GetIndexOfChildWithName(lldb::opaque_compiler_type_t type,
                                            llvm::StringRef name,
                                            bool omit_empty_base_classes) {
  return UINT32_MAX; // minillvm everything is unnamed; we cannot accesss by
                     // name
}

#pragma mark C++ Base Classes

#pragma mark TagDecl

// Dumping types
#define DEPTH_INCREMENT 2

#ifndef NDEBUG
LLVM_DUMP_METHOD void
TypeSystemMiniLLVM::dump(lldb::opaque_compiler_type_t type) const {
  if (!type)
    return;
  auto mini_type = GetMiniType(type);
  mini_type.getType()->dump();
}
#endif

void TypeSystemMiniLLVM::Dump(llvm::raw_ostream &output) {
  output << "dumping not implemented" << '\n';
}

bool TypeSystemMiniLLVM::DumpTypeValue(
    lldb::opaque_compiler_type_t type, Stream &s, lldb::Format format,
    const lldb_private::DataExtractor &data, lldb::offset_t byte_offset,
    size_t byte_size, uint32_t bitfield_bit_size, uint32_t bitfield_bit_offset,
    ExecutionContextScope *exe_scope) {
  if (!type)
    return false;
  if (IsAggregateType(type)) {
    return false;
  } else {
    {
      // We are down to a scalar type that we just need to display.
      {
        uint32_t item_count = 1;
        // A few formats, we might need to modify our size and count for
        // depending
        // on how we are trying to display the value...
        switch (format) {
        default:
        case eFormatBoolean:
        case eFormatBinary:
        case eFormatComplex:
        case eFormatCString: // NULL terminated C strings
        case eFormatDecimal:
        case eFormatEnum:
        case eFormatHex:
        case eFormatHexUppercase:
        case eFormatFloat:
        case eFormatOctal:
        case eFormatOSType:
        case eFormatUnsigned:
        case eFormatPointer:
        case eFormatVectorOfChar:
        case eFormatVectorOfSInt8:
        case eFormatVectorOfUInt8:
        case eFormatVectorOfSInt16:
        case eFormatVectorOfUInt16:
        case eFormatVectorOfSInt32:
        case eFormatVectorOfUInt32:
        case eFormatVectorOfSInt64:
        case eFormatVectorOfUInt64:
        case eFormatVectorOfFloat32:
        case eFormatVectorOfFloat64:
        case eFormatVectorOfUInt128:
          break;

        case eFormatChar:
        case eFormatCharPrintable:
        case eFormatCharArray:
        case eFormatBytes:
        case eFormatUnicode8:
        case eFormatBytesWithASCII:
          item_count = byte_size;
          byte_size = 1;
          break;

        case eFormatUnicode16:
          item_count = byte_size / 2;
          byte_size = 2;
          break;

        case eFormatUnicode32:
          item_count = byte_size / 4;
          byte_size = 4;
          break;
        }
        return DumpDataExtractor(data, &s, byte_offset, format, byte_size,
                                 item_count, UINT32_MAX, LLDB_INVALID_ADDRESS,
                                 bitfield_bit_size, bitfield_bit_offset,
                                 exe_scope);
      }
    }
  }
  return false;
}

void TypeSystemMiniLLVM::DumpTypeDescription(lldb::opaque_compiler_type_t type,
                                             lldb::DescriptionLevel level) {
  StreamFile s(stdout, false);
  DumpTypeDescription(type, s, level);
}

void TypeSystemMiniLLVM::DumpTypeDescription(lldb::opaque_compiler_type_t type,
                                             Stream &s,
                                             lldb::DescriptionLevel level) {
  if (type) {
    auto mini_type = GetMiniType(type);

    llvm::SmallVector<char, 1024> buf;
    llvm::raw_svector_ostream llvm_ostrm(buf);

    switch (mini_type.getType()->getTypeID()) {
    case llvm::Type::StructTyID: {
      auto *struct_type = llvm::cast<llvm::StructType>(mini_type.getType());
      if (struct_type->isOpaque()) {
        s.PutCString("opaque struct");
        return;
      }
      if (level == eDescriptionLevelFull) {
        struct_type->print(llvm_ostrm, 0);
      } else {
        s.PutCString(struct_type->getName().str());
      }
    } break;
    default: {
      if (level == eDescriptionLevelVerbose)
        mini_type.getType()->print(llvm_ostrm);
      else {
        mini_type.getType()->print(llvm_ostrm, 0);
      }
    }
    }

    if (buf.size() > 0) {
      s.Write(buf.data(), buf.size());
    }
  }
}

// CompilerDecl override functions
// TODO: CompilerDecl

ConstString TypeSystemMiniLLVM::DeclGetName(void *opaque_decl) {
  return ConstString();
}

// CompilerDeclContext functions

ConstString TypeSystemMiniLLVM::DeclContextGetName(void *opaque_decl_ctx) {
  return ConstString();
}

ConstString
TypeSystemMiniLLVM::DeclContextGetScopeQualifiedName(void *opaque_decl_ctx) {
  return ConstString();
}

bool TypeSystemMiniLLVM::DeclContextIsClassMethod(void *opaque_decl_ctx) {
  return false;
}

bool TypeSystemMiniLLVM::DeclContextIsContainedInLookup(
    void *opaque_decl_ctx, void *other_opaque_decl_ctx) {
  return false;
}

lldb::LanguageType
TypeSystemMiniLLVM::DeclContextGetLanguage(void *opaque_decl_ctx) {
  if (!opaque_decl_ctx)
    return eLanguageTypeUnknown;
  return eLanguageTypeMiniLLVM;
}

char ScratchTypeSystemMiniLLVM::ID;
const std::nullopt_t ScratchTypeSystemMiniLLVM::DefaultAST = std::nullopt;

ScratchTypeSystemMiniLLVM::ScratchTypeSystemMiniLLVM(Target &target,
                                                     llvm::Triple triple)
    : TypeSystemMiniLLVM("scratch ASTContext", triple), m_triple(triple),
      m_target_wp(target.shared_from_this())  {}

void ScratchTypeSystemMiniLLVM::Finalize() { TypeSystemMiniLLVM::Finalize(); }

TypeSystemMiniLLVMSP
ScratchTypeSystemMiniLLVM::GetForTarget(Target &target,
                                        std::optional<IsolatedASTKind> ast_kind,
                                        bool create_on_demand) {
  auto type_system_or_err = target.GetScratchTypeSystemForLanguage(
      lldb::eLanguageTypeMiniLLVM, create_on_demand);
  if (auto err = type_system_or_err.takeError()) {
    LLDB_LOG_ERROR(GetLog(LLDBLog::Target), std::move(err),
                   "Couldn't get scratch TypeSystemMiniLLVM: {0}");
    return nullptr;
  }
  auto ts_sp = *type_system_or_err;
  ScratchTypeSystemMiniLLVM *scratch_ast =
      llvm::dyn_cast_or_null<ScratchTypeSystemMiniLLVM>(ts_sp.get());
  if (!scratch_ast)
    return nullptr;
  // If no dedicated sub-AST was requested, just return the main AST.
  if (ast_kind == DefaultAST)
    return std::static_pointer_cast<TypeSystemMiniLLVM>(ts_sp);
  // Search the sub-ASTs.
  return std::static_pointer_cast<TypeSystemMiniLLVM>(
      scratch_ast->GetIsolatedAST(*ast_kind).shared_from_this());
}

/// Returns a human-readable name that uniquely identifiers the sub-AST kind.
static llvm::StringRef
GetNameForIsolatedASTKind(ScratchTypeSystemMiniLLVM::IsolatedASTKind kind) {
  switch (kind) {
  case ScratchTypeSystemMiniLLVM::IsolatedASTKind::CppModules:
    return "C++ modules";
  }
  llvm_unreachable("Unimplemented IsolatedASTKind?");
}

void ScratchTypeSystemMiniLLVM::Dump(llvm::raw_ostream &output) {
  // First dump the main scratch AST.
  output << "State of scratch MiniLLVM type system:\n";
  TypeSystemMiniLLVM::Dump(output);

  // Now sort the isolated sub-ASTs.
  typedef std::pair<IsolatedASTKey, TypeSystem *> KeyAndTS;
  std::vector<KeyAndTS> sorted_typesystems;
  for (const auto &a : m_isolated_asts)
    sorted_typesystems.emplace_back(a.first, a.second.get());
  llvm::stable_sort(sorted_typesystems, llvm::less_first());

  // Dump each sub-AST too.
  for (const auto &a : sorted_typesystems) {
    IsolatedASTKind kind =
        static_cast<ScratchTypeSystemMiniLLVM::IsolatedASTKind>(a.first);
    output << "State of scratch MiniLLVM type subsystem "
           << GetNameForIsolatedASTKind(kind) << ":\n";
    a.second->Dump(output);
  }
}

UserExpression *ScratchTypeSystemMiniLLVM::GetUserExpression(
    llvm::StringRef expr, llvm::StringRef prefix, SourceLanguage language,
    Expression::ResultType desired_type,
    const EvaluateExpressionOptions &options, ValueObject *ctx_obj) {
  TargetSP target_sp = m_target_wp.lock();
  if (!target_sp)
    return nullptr;

  return new ClangUserExpression(*target_sp.get(), expr, prefix, language,
                                 desired_type, options, ctx_obj);
}

FunctionCaller *ScratchTypeSystemMiniLLVM::GetFunctionCaller(
    const CompilerType &return_type, const Address &function_address,
    const ValueList &arg_value_list, const char *name) {
  TargetSP target_sp = m_target_wp.lock();
  if (!target_sp)
    return nullptr;

  Process *process = target_sp->GetProcessSP().get();
  if (!process)
    return nullptr;

  return new ClangFunctionCaller(*process, return_type, function_address,
                                 arg_value_list, name);
}

std::unique_ptr<UtilityFunction>
ScratchTypeSystemMiniLLVM::CreateUtilityFunction(std::string text,
                                                 std::string name) {
  TargetSP target_sp = m_target_wp.lock();
  if (!target_sp)
    return {};

  return std::make_unique<MiniLLVMUtilityFunction>(
      *target_sp.get(), std::move(text), std::move(name),
      target_sp->GetDebugUtilityExpression());
}

static llvm::StringRef
GetSpecializedASTName(ScratchTypeSystemMiniLLVM::IsolatedASTKind feature) {
  switch (feature) {
  case ScratchTypeSystemMiniLLVM::IsolatedASTKind::CppModules:
    return "scratch ASTContext for C++ module types";
  }
  llvm_unreachable("Unimplemented ASTFeature kind?");
}

TypeSystemMiniLLVM &ScratchTypeSystemMiniLLVM::GetIsolatedAST(
    ScratchTypeSystemMiniLLVM::IsolatedASTKind feature) {
  auto found_ast = m_isolated_asts.find(feature);
  if (found_ast != m_isolated_asts.end())
    return *found_ast->second;

  // Couldn't find the requested sub-AST, so create it now.
  std::shared_ptr<TypeSystemMiniLLVM> new_ast_sp =
      std::make_shared<TypeSystemMiniLLVM>(GetSpecializedASTName(feature),
                                           m_triple);
  m_isolated_asts.insert({feature, new_ast_sp});
  return *new_ast_sp;
}

void TypeSystemMiniLLVM::LogCreation() const {
  if (auto *log = GetLog(LLDBLog::Expressions))
    LLDB_LOG(log, "Created new TypeSystem for (ASTContext*){0:x} '{1}'",
             &getLLVMContext(), getDisplayName());
}
