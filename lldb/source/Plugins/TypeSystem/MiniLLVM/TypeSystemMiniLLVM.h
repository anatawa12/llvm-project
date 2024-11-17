//===-- TypeSystemMiniLLVM.h ---------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_SOURCE_PLUGINS_TYPESYSTEM_MINILLVM_TYPESYSTEMINILLVM_H
#define LLDB_SOURCE_PLUGINS_TYPESYSTEM_MINILLVM_TYPESYSTEMINILLVM_H

#include <cstdint>

#include <functional>
#include <initializer_list>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "llvm/ADT/APSInt.h"
#include "llvm/ADT/SmallVector.h"

#include "Plugins/ExpressionParser/Clang/ClangASTMetadata.h"
#include "lldb/Expression/ExpressionVariable.h"
#include "lldb/Symbol/CompilerType.h"
#include "lldb/Symbol/TypeSystem.h"
#include "lldb/Target/Target.h"
#include "lldb/Utility/ConstString.h"
#include "lldb/Utility/Flags.h"
#include "lldb/Utility/Log.h"
#include "lldb/lldb-enumerations.h"

namespace llvm {
class Module;
class LLVMContext;
} // namespace llvm

namespace lldb_private {

class Declaration;
struct MiniLLVMType;
struct MiniLLVMTargetInfo;
struct MiniLLVMContext;

/// A mini TypeSystem implementation based on llvm.
class TypeSystemMiniLLVM : public TypeSystem {
  // LLVM RTTI support
  static char ID;

public:
  // llvm casting support
  bool isA(const void *ClassID) const override { return ClassID == &ID; }
  static bool classof(const TypeSystem *ts) { return ts->isA(&ID); }

  /// Constructs a TypeSystemMiniLLVM with an ASTContext using the given triple.
  ///
  /// \param name The name for the TypeSystemMiniLLVM (for logging purposes)
  /// \param triple The llvm::Triple used for the ASTContext. The triple defines
  ///               certain characteristics of the ASTContext and its types
  ///               (e.g., whether certain primitive types exist or what their
  ///               signedness is).
  explicit TypeSystemMiniLLVM(llvm::StringRef name, llvm::Triple triple);

  /// Constructs a TypeSystemMiniLLVM that uses an existing ASTContext internally.
  /// Useful when having an existing MiniLLVMContext that should be used.
  ///
  /// \param name The name for the TypeSystemMiniLLVM (for logging purposes)
  /// \param existing_ctxt An existing ASTContext.
  explicit TypeSystemMiniLLVM(llvm::StringRef name,
                              MiniLLVMContext &existing_ctxt);

  ~TypeSystemMiniLLVM() override;

  void Finalize() override;

  // PluginInterface functions
  llvm::StringRef GetPluginName() override { return GetPluginNameStatic(); }

  static llvm::StringRef GetPluginNameStatic() { return "miniLLVM"; }

  static lldb::TypeSystemSP CreateInstance(lldb::LanguageType language,
                                           Module *module, Target *target);

  static LanguageSet GetSupportedLanguagesForTypes();
  static LanguageSet GetSupportedLanguagesForExpressions();

  static void Initialize();

  static void Terminate();

  const char *GetTargetTriple();

  llvm::StringRef getDisplayName() const { return m_display_name; }

  // Basic Types
  CompilerType GetBuiltinTypeForEncodingAndBitSize(lldb::Encoding encoding,
                                                   size_t bit_size) override;

  uint32_t GetPointerByteSize() override;

  // CompilerDecl override functions
  ConstString DeclGetName(void *opaque_decl) override;

  CompilerType GetTypeForDecl(void *opaque_decl) override;

  // CompilerDeclContext override functions

  ConstString DeclContextGetName(void *opaque_decl_ctx) override;

  ConstString DeclContextGetScopeQualifiedName(void *opaque_decl_ctx) override;

  bool DeclContextIsClassMethod(void *opaque_decl_ctx) override;

  bool DeclContextIsContainedInLookup(void *opaque_decl_ctx,
                                      void *other_opaque_decl_ctx) override;

  lldb::LanguageType DeclContextGetLanguage(void *opaque_decl_ctx) override;

  // Tests

#ifndef NDEBUG
  bool Verify(lldb::opaque_compiler_type_t type) override;
#endif

  bool IsArrayType(lldb::opaque_compiler_type_t type,
                   CompilerType *element_type, uint64_t *size,
                   bool *is_incomplete) override;

  bool IsVectorType(lldb::opaque_compiler_type_t type,
                    CompilerType *element_type, uint64_t *size) override;

  bool IsAggregateType(lldb::opaque_compiler_type_t type) override;

  bool IsAnonymousType(lldb::opaque_compiler_type_t type) override;

  bool IsBeingDefined(lldb::opaque_compiler_type_t type) override;

  bool IsCharType(lldb::opaque_compiler_type_t type) override;

  bool IsCompleteType(lldb::opaque_compiler_type_t type) override;

  bool IsConst(lldb::opaque_compiler_type_t type) override;

  bool IsDefined(lldb::opaque_compiler_type_t type) override;

  bool IsFloatingPointType(lldb::opaque_compiler_type_t type, uint32_t &count,
                           bool &is_complex) override;

  unsigned GetPtrAuthKey(lldb::opaque_compiler_type_t type) override;
  unsigned GetPtrAuthDiscriminator(lldb::opaque_compiler_type_t type) override;
  bool GetPtrAuthAddressDiversity(lldb::opaque_compiler_type_t type) override;

  bool IsFunctionType(lldb::opaque_compiler_type_t type) override;

  uint32_t IsHomogeneousAggregate(lldb::opaque_compiler_type_t type,
                                  CompilerType *base_type_ptr) override;

  size_t
  GetNumberOfFunctionArguments(lldb::opaque_compiler_type_t type) override;

  CompilerType GetFunctionArgumentAtIndex(lldb::opaque_compiler_type_t type,
                                          const size_t index) override;

  bool IsFunctionPointerType(lldb::opaque_compiler_type_t type) override;

  bool IsMemberFunctionPointerType(lldb::opaque_compiler_type_t type) override;

  bool IsBlockPointerType(lldb::opaque_compiler_type_t type,
                          CompilerType *function_pointer_type_ptr) override;

  bool IsIntegerType(lldb::opaque_compiler_type_t type,
                     bool &is_signed) override;

  bool IsEnumerationType(lldb::opaque_compiler_type_t type,
                         bool &is_signed) override;

  bool IsScopedEnumerationType(lldb::opaque_compiler_type_t type) override;

  bool IsPolymorphicClass(lldb::opaque_compiler_type_t type) override;

  bool IsPossibleDynamicType(lldb::opaque_compiler_type_t type,
                             CompilerType *target_type, // Can pass nullptr
                             bool check_cplusplus, bool check_objc) override;

  bool IsRuntimeGeneratedType(lldb::opaque_compiler_type_t type) override;

  bool IsPointerType(lldb::opaque_compiler_type_t type,
                     CompilerType *pointee_type) override;

  bool IsPointerOrReferenceType(lldb::opaque_compiler_type_t type,
                                CompilerType *pointee_type) override;

  bool IsReferenceType(lldb::opaque_compiler_type_t type,
                       CompilerType *pointee_type, bool *is_rvalue) override;

  bool IsScalarType(lldb::opaque_compiler_type_t type) override;

  bool IsTypedefType(lldb::opaque_compiler_type_t type) override;

  bool IsVoidType(lldb::opaque_compiler_type_t type) override;

  bool CanPassInRegisters(const CompilerType &type) override;

  bool SupportsLanguage(lldb::LanguageType language) override;

  // Type Completion

  bool GetCompleteType(lldb::opaque_compiler_type_t type) override;

  // Accessors

  ConstString GetTypeName(lldb::opaque_compiler_type_t type,
                          bool base_only) override;

  ConstString GetDisplayTypeName(lldb::opaque_compiler_type_t type) override;

  uint32_t GetTypeInfo(lldb::opaque_compiler_type_t type,
                       CompilerType *pointee_or_type) override;

  lldb::LanguageType
  GetMinimumLanguage(lldb::opaque_compiler_type_t type) override;

  lldb::TypeClass GetTypeClass(lldb::opaque_compiler_type_t type) override;

  unsigned GetTypeQualifiers(lldb::opaque_compiler_type_t type) override;

  // Creating related types

  CompilerType GetArrayElementType(lldb::opaque_compiler_type_t type,
                                   ExecutionContextScope *exe_scope) override;

  CompilerType GetArrayType(lldb::opaque_compiler_type_t type,
                            uint64_t size) override;

  CompilerType GetCanonicalType(lldb::opaque_compiler_type_t type) override;

  CompilerType
  GetFullyUnqualifiedType(lldb::opaque_compiler_type_t type) override;

  CompilerType
  GetEnumerationIntegerType(lldb::opaque_compiler_type_t type) override;

  // Returns -1 if this isn't a function of if the function doesn't have a
  // prototype Returns a value >= 0 if there is a prototype.
  int GetFunctionArgumentCount(lldb::opaque_compiler_type_t type) override;

  CompilerType GetFunctionArgumentTypeAtIndex(lldb::opaque_compiler_type_t type,
                                              size_t idx) override;

  CompilerType
  GetFunctionReturnType(lldb::opaque_compiler_type_t type) override;

  size_t GetNumMemberFunctions(lldb::opaque_compiler_type_t type) override;

  TypeMemberFunctionImpl
  GetMemberFunctionAtIndex(lldb::opaque_compiler_type_t type,
                           size_t idx) override;

  CompilerType GetNonReferenceType(lldb::opaque_compiler_type_t type) override;

  CompilerType GetPointeeType(lldb::opaque_compiler_type_t type) override;

  CompilerType GetPointerType(lldb::opaque_compiler_type_t type) override;

  CompilerType
  GetLValueReferenceType(lldb::opaque_compiler_type_t type) override;

  CompilerType
  GetRValueReferenceType(lldb::opaque_compiler_type_t type) override;

  CompilerType GetAtomicType(lldb::opaque_compiler_type_t type) override;

  CompilerType AddConstModifier(lldb::opaque_compiler_type_t type) override;

  CompilerType AddPtrAuthModifier(lldb::opaque_compiler_type_t type,
                                  uint32_t payload) override;

  CompilerType AddVolatileModifier(lldb::opaque_compiler_type_t type) override;

  CompilerType AddRestrictModifier(lldb::opaque_compiler_type_t type) override;

  /// Using the current type, create a new typedef to that type using
  /// "typedef_name" as the name and "decl_ctx" as the decl context.
  /// \param opaque_payload is an opaque TypePayloadClang.
  CompilerType CreateTypedef(lldb::opaque_compiler_type_t type,
                             const char *name,
                             const CompilerDeclContext &decl_ctx,
                             uint32_t opaque_payload) override;

  // If the current object represents a typedef type, get the underlying type
  CompilerType GetTypedefedType(lldb::opaque_compiler_type_t type) override;

  // Create related types using the current type's AST
  CompilerType GetBasicTypeFromAST(lldb::BasicType basic_type) override;

  // Create a generic function prototype that can be used in ValuObject types
  // to correctly display a function pointer with the right value and summary.
  CompilerType CreateGenericFunctionPrototype() override;

  // Exploring the type

  const llvm::fltSemantics &GetFloatTypeSemantics(size_t byte_size) override;

  std::optional<uint64_t> GetByteSize(lldb::opaque_compiler_type_t type,
                                      ExecutionContextScope *exe_scope) {
    if (std::optional<uint64_t> bit_size = GetBitSize(type, exe_scope))
      return (*bit_size + 7) / 8;
    return std::nullopt;
  }

  std::optional<uint64_t> GetBitSize(lldb::opaque_compiler_type_t type,
                                     ExecutionContextScope *exe_scope) override;

  lldb::Encoding GetEncoding(lldb::opaque_compiler_type_t type,
                             uint64_t &count) override;

  lldb::Format GetFormat(lldb::opaque_compiler_type_t type) override;

  std::optional<size_t>
  GetTypeBitAlign(lldb::opaque_compiler_type_t type,
                  ExecutionContextScope *exe_scope) override;

  llvm::Expected<uint32_t>
  GetNumChildren(lldb::opaque_compiler_type_t type,
                 bool omit_empty_base_classes,
                 const ExecutionContext *exe_ctx) override;

  CompilerType GetBuiltinTypeByName(ConstString name) override;

  lldb::BasicType
  GetBasicTypeEnumeration(lldb::opaque_compiler_type_t type) override;

  void ForEachEnumerator(
      lldb::opaque_compiler_type_t type,
      std::function<bool(const CompilerType &integer_type,
                         ConstString name,
                         const llvm::APSInt &value)> const &callback) override;

  uint32_t GetNumFields(lldb::opaque_compiler_type_t type) override;

  CompilerType GetFieldAtIndex(lldb::opaque_compiler_type_t type, size_t idx,
                               std::string &name, uint64_t *bit_offset_ptr,
                               uint32_t *bitfield_bit_size_ptr,
                               bool *is_bitfield_ptr) override;

  uint32_t GetNumDirectBaseClasses(lldb::opaque_compiler_type_t type) override;

  uint32_t GetNumVirtualBaseClasses(lldb::opaque_compiler_type_t type) override;

  CompilerType GetDirectBaseClassAtIndex(lldb::opaque_compiler_type_t type,
                                         size_t idx,
                                         uint32_t *bit_offset_ptr) override;

  CompilerType GetVirtualBaseClassAtIndex(lldb::opaque_compiler_type_t type,
                                          size_t idx,
                                          uint32_t *bit_offset_ptr) override;

  CompilerDecl GetStaticFieldWithName(lldb::opaque_compiler_type_t type,
                                      llvm::StringRef name) override;

  llvm::Expected<CompilerType> GetChildCompilerTypeAtIndex(
      lldb::opaque_compiler_type_t type, ExecutionContext *exe_ctx, size_t idx,
      bool transparent_pointers, bool omit_empty_base_classes,
      bool ignore_array_bounds, std::string &child_name,
      uint32_t &child_byte_size, int32_t &child_byte_offset,
      uint32_t &child_bitfield_bit_size, uint32_t &child_bitfield_bit_offset,
      bool &child_is_base_class, bool &child_is_deref_of_parent,
      ValueObject *valobj, uint64_t &language_flags) override;

  // Lookup a child given a name. This function will match base class names and
  // member member names in "clang_type" only, not descendants.
  uint32_t GetIndexOfChildWithName(lldb::opaque_compiler_type_t type,
                                   llvm::StringRef name,
                                   bool omit_empty_base_classes) override;

  // Lookup a child member given a name. This function will match member names
  // only and will descend into "clang_type" children in search for the first
  // member in this class, or any base class that matches "name".
  // TODO: Return all matches for a given name by returning a
  // vector<vector<uint32_t>>
  // so we catch all names that match a given child name, not just the first.
  size_t
  GetIndexOfChildMemberWithName(lldb::opaque_compiler_type_t type,
                                llvm::StringRef name,
                                bool omit_empty_base_classes,
                                std::vector<uint32_t> &child_indexes) override;

  // Dumping types
#ifndef NDEBUG
  /// Convenience LLVM-style dump method for use in the debugger only.
  /// In contrast to the other \p Dump() methods this directly invokes
  /// \p clang::QualType::dump().
  LLVM_DUMP_METHOD void dump(lldb::opaque_compiler_type_t type) const override;
#endif

  /// \see lldb_private::TypeSystem::Dump
  void Dump(llvm::raw_ostream &output) override;

  bool DumpTypeValue(lldb::opaque_compiler_type_t type, Stream &s,
                     lldb::Format format, const DataExtractor &data,
                     lldb::offset_t data_offset, size_t data_byte_size,
                     uint32_t bitfield_bit_size, uint32_t bitfield_bit_offset,
                     ExecutionContextScope *exe_scope) override;

  void DumpTypeDescription(
      lldb::opaque_compiler_type_t type,
      lldb::DescriptionLevel level = lldb::eDescriptionLevelFull) override;

  void DumpTypeDescription(
      lldb::opaque_compiler_type_t type, Stream &s,
      lldb::DescriptionLevel level = lldb::eDescriptionLevelFull) override;

private:
  /// Emits information about this TypeSystem into the expression log.
  ///
  /// Helper method that is used in \ref TypeSystemMiniLLVM::TypeSystemMiniLLVM
  /// on creation of a new instance.
  void LogCreation() const;

  // Classes that inherit from TypeSystemMiniLLVM can see and modify these
  std::string m_target_triple;
  uint32_t m_pointer_byte_size = 0;
  bool m_context_owned = false;
  /// A string describing what this TypeSystemMiniLLVM represents (e.g.,
  /// AST for debug information, an expression, some other utility ClangAST).
  /// Useful for logging and debugging.
  std::string m_display_name;

  // For TypeSystemMiniLLVM only
  TypeSystemMiniLLVM(const TypeSystemMiniLLVM &);
  const TypeSystemMiniLLVM &operator=(const TypeSystemMiniLLVM &);
  /// Creates the internal ASTContext.
  void SetTargetTriple(llvm::StringRef target_triple);

  std::unique_ptr<MiniLLVMContext> m_context;

  llvm::LLVMContext &getLLVMContext() const;
  llvm::Module &getLLVMModule() const;
  CompilerType GetType(MiniLLVMType type);
  MiniLLVMType GetMiniType(lldb::opaque_compiler_type_t type) const;
  const MiniLLVMTargetInfo &getTargetInfo() const;

  void CreateLLVMContext();
};

/// The TypeSystemMiniLLVM instance used for the scratch ASTContext in a
/// lldb::Target.
class ScratchTypeSystemMiniLLVM : public TypeSystemMiniLLVM {
  /// LLVM RTTI support
  static char ID;

public:
  ScratchTypeSystemMiniLLVM(Target &target, llvm::Triple triple);

  ~ScratchTypeSystemMiniLLVM() override = default;

  void Finalize() override;

  /// The different kinds of isolated ASTs within the scratch TypeSystem.
  ///
  /// These ASTs are isolated from the main scratch AST and are each
  /// dedicated to a special language option/feature that makes the contained
  /// AST nodes incompatible with other AST nodes.
  enum IsolatedASTKind {
    /// The isolated AST for declarations/types from expressions that imported
    /// type information from a C++ module. The templates from a C++ module
    /// often conflict with the templates we generate from debug information,
    /// so we put these types in their own AST.
    CppModules
  };

  /// Alias for requesting the default scratch TypeSystemMiniLLVM in GetForTarget.
  // This isn't constexpr as gtest/std::optional comparison logic is trying
  // to get the address of this for pretty-printing.
  static const std::nullopt_t DefaultAST;

  /// Returns the scratch TypeSystemMiniLLVM for the given target.
  /// \param target The Target which scratch TypeSystemMiniLLVM should be returned.
  /// \param ast_kind Allows requesting a specific sub-AST instead of the
  ///                 default scratch AST. See also `IsolatedASTKind`.
  /// \param create_on_demand If the scratch TypeSystemMiniLLVM instance can be
  /// created by this call if it doesn't exist yet. If it doesn't exist yet and
  /// this parameter is false, this function returns a nullptr.
  /// \return The scratch type system of the target or a nullptr in case an
  ///         error occurred.
  static lldb::TypeSystemMiniLLVMSP
  GetForTarget(Target &target,
               std::optional<IsolatedASTKind> ast_kind = DefaultAST,
               bool create_on_demand = true);

  /// \see lldb_private::TypeSystem::Dump
  void Dump(llvm::raw_ostream &output) override;

  UserExpression *GetUserExpression(llvm::StringRef expr,
                                    llvm::StringRef prefix,
                                    SourceLanguage language,
                                    Expression::ResultType desired_type,
                                    const EvaluateExpressionOptions &options,
                                    ValueObject *ctx_obj) override;

  FunctionCaller *GetFunctionCaller(const CompilerType &return_type,
                                    const Address &function_address,
                                    const ValueList &arg_value_list,
                                    const char *name) override;

  std::unique_ptr<UtilityFunction>
  CreateUtilityFunction(std::string text, std::string name) override;

  // llvm casting support
  bool isA(const void *ClassID) const override {
    return ClassID == &ID || TypeSystemMiniLLVM::isA(ClassID);
  }
  static bool classof(const TypeSystem *ts) { return ts->isA(&ID); }

private:
  /// Returns the requested sub-AST.
  /// Will lazily create the sub-AST if it hasn't been created before.
  TypeSystemMiniLLVM &GetIsolatedAST(IsolatedASTKind feature);

  /// The target triple.
  /// This was potentially adjusted and might not be identical to the triple
  /// of `m_target_wp`.
  llvm::Triple m_triple;
  lldb::TargetWP m_target_wp;

  // FIXME: GCC 5.x doesn't support enum as map keys.
  typedef int IsolatedASTKey;

  /// Map from IsolatedASTKind to their actual TypeSystemMiniLLVM instance.
  /// This map is lazily filled with sub-ASTs and should be accessed via
  /// `GetSubAST` (which lazily fills this map).
  llvm::DenseMap<IsolatedASTKey, std::shared_ptr<TypeSystemMiniLLVM>>
      m_isolated_asts;
};

} // namespace lldb_private

#endif // LLDB_SOURCE_PLUGINS_TYPESYSTEM_MINILLVM_TYPESYSTEMINILLVM_H
