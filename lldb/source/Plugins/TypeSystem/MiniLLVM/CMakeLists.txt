add_lldb_library(lldbPluginTypeSystemMiniLLVM PLUGIN
  TypeSystemMiniLLVM.cpp

  LINK_LIBS
    lldbCore
    lldbSymbol
    lldbTarget
    lldbUtility
    lldbPluginExpressionParserMiniLLVM
  LINK_COMPONENTS
    Support
)
