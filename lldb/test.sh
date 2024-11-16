#!/bin/sh

nm "$@" > all_symbols.txt
<all_symbols.txt grep -E ' [BDTWS] ' | sed -e 's/.* [BDTWS] //' | sort -u > defined.txt
<all_symbols.txt grep ' U ' | sed -e 's/.* U //' | sort -u > obj_undefined.txt
comm -13 defined.txt obj_undefined.txt | tee undefined.txt
