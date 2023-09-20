# Resolve all symbols
set env LD_BIND_NOW=1
# Breakpoint at main
b main
# Run until breakpoint
run
# Save a core file
generate-core-file ${core_file}
# End session
kill
quit