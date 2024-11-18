add_lldb_library(lldbPluginTypeSystemMiniLLVM PLUGIN
  TypeSystemMiniLLVM.cpp

  LINK_LIBS
    lldbCore
    lldbSymbol
    lldbTarget
    lldbUtility
    lldbPluginExpressionParserMiniLLVM
    lldbPluginSymbolFileDWARF
    lldbPluginSymbolFilePDB
  LINK_COMPONENTS
    Support
)
