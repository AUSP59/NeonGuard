
Param([string]$Config="Release")
cmake -S . -B build -DCMAKE_BUILD_TYPE=$Config
cmake --build build --config $Config
