cmake_minimum_required(VERSION 3.13)
project(pollen C)

# Output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# List of eBPF source files
set(BPF_SOURCES
	src/forkMonitor.c
)

# Generate BPF object names
set(BPF_OBJECTS "")
foreach(BPF_FILE ${BPF_SOURCES})
    get_filename_component(BPF_NAME ${BPF_FILE} NAME_WE)
    set(BPF_OBJ ${BPF_NAME}.bpf.o)
    list(APPEND BPF_OBJECTS ${BPF_OBJ})

    add_custom_command(
            OUTPUT ${BPF_OBJ}
            COMMAND clang -O2 -Wall -Werror -target bpf -g
            -D__TARGET_ARCH_x86
            -c ${BPF_FILE}
            -o ${BPF_OBJ}
            -I include
            DEPENDS ${BPF_FILE}
            COMMENT "Compiling eBPF program: ${BPF_FILE}"
    )
endforeach()

# Create a single target for all BPF objects
add_custom_target(
        ebpf ALL
        DEPENDS ${BPF_OBJECTS}
)
