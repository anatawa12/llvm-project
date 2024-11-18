add_lldb_library(lldbPluginTypeSystemMiniLLVM PLUGIN
  TypeSystemMiniLLVM.cpp

  LINK_LIBS
    lldbCore
    lldbSymbol
    lldbTarget
    lldbUtility
    lldbPluginExpressionParserClang
    lldbPluginExpressionParserMiniLLVM
    lldbPluginSymbolFileDWARF
    lldbPluginSymbolFilePDB
    lldbPluginObjCRuntime
  CLANG_LIBS
    clangAST
    clangBasic
    clangFrontend
    clangSema
  LINK_COMPONENTS
    Support
)
