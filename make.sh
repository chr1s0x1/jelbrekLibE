#!/bin/bash

xcrun -sdk iphoneos clang -arch arm64e -arch arm64 -dynamiclib  -lc++ -framework UIKit -framework IOKit -install_name "@executable_path/jelbrekLibE.dylib" -Iinclude -Ipatchfinder64/kerneldec/lzfse/ -fobjc-arc patchfinder64/kerneldec/*.c patchfinder64/kerneldec/*.cpp patchfinder64/kerneldec/lzfse/*.c *.c *.m -o downloads/jelbrekLibE.dylib
