# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/cliff/work/challenges/patch/challenge/cfs/cfe

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/cliff/work/challenges/patch/challenge/cfs/build/cpu1

# Include any dependencies generated for this target.
include cpu1/CMakeFiles/core-cpu1.dir/depend.make

# Include the progress variables for this target.
include cpu1/CMakeFiles/core-cpu1.dir/progress.make

# Include the compile flags for this target's objects.
include cpu1/CMakeFiles/core-cpu1.dir/flags.make

cpu1/CMakeFiles/core-cpu1.dir/src/target_config.c.o: cpu1/CMakeFiles/core-cpu1.dir/flags.make
cpu1/CMakeFiles/core-cpu1.dir/src/target_config.c.o: /home/cliff/work/challenges/patch/challenge/cfs/cfe/cmake/target/src/target_config.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/cliff/work/challenges/patch/challenge/cfs/build/cpu1/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object cpu1/CMakeFiles/core-cpu1.dir/src/target_config.c.o"
	cd /home/cliff/work/challenges/patch/challenge/cfs/build/cpu1/cpu1 && /usr/bin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/core-cpu1.dir/src/target_config.c.o   -c /home/cliff/work/challenges/patch/challenge/cfs/cfe/cmake/target/src/target_config.c

cpu1/CMakeFiles/core-cpu1.dir/src/target_config.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/core-cpu1.dir/src/target_config.c.i"
	cd /home/cliff/work/challenges/patch/challenge/cfs/build/cpu1/cpu1 && /usr/bin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/cliff/work/challenges/patch/challenge/cfs/cfe/cmake/target/src/target_config.c > CMakeFiles/core-cpu1.dir/src/target_config.c.i

cpu1/CMakeFiles/core-cpu1.dir/src/target_config.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/core-cpu1.dir/src/target_config.c.s"
	cd /home/cliff/work/challenges/patch/challenge/cfs/build/cpu1/cpu1 && /usr/bin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/cliff/work/challenges/patch/challenge/cfs/cfe/cmake/target/src/target_config.c -o CMakeFiles/core-cpu1.dir/src/target_config.c.s

cpu1/CMakeFiles/core-cpu1.dir/src/target_config.c.o.requires:

.PHONY : cpu1/CMakeFiles/core-cpu1.dir/src/target_config.c.o.requires

cpu1/CMakeFiles/core-cpu1.dir/src/target_config.c.o.provides: cpu1/CMakeFiles/core-cpu1.dir/src/target_config.c.o.requires
	$(MAKE) -f cpu1/CMakeFiles/core-cpu1.dir/build.make cpu1/CMakeFiles/core-cpu1.dir/src/target_config.c.o.provides.build
.PHONY : cpu1/CMakeFiles/core-cpu1.dir/src/target_config.c.o.provides

cpu1/CMakeFiles/core-cpu1.dir/src/target_config.c.o.provides.build: cpu1/CMakeFiles/core-cpu1.dir/src/target_config.c.o


# Object files for target core-cpu1
core__cpu1_OBJECTS = \
"CMakeFiles/core-cpu1.dir/src/target_config.c.o"

# External object files for target core-cpu1
core__cpu1_EXTERNAL_OBJECTS =

cpu1/core-cpu1: cpu1/CMakeFiles/core-cpu1.dir/src/target_config.c.o
cpu1/core-cpu1: cpu1/CMakeFiles/core-cpu1.dir/build.make
cpu1/core-cpu1: cfe_core_default_cpu1/libcfe_core_default_cpu1.a
cpu1/core-cpu1: psp/pc-linux/libpsp-pc-linux.a
cpu1/core-cpu1: osal/libosal.a
cpu1/core-cpu1: cpu1/CMakeFiles/core-cpu1.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/cliff/work/challenges/patch/challenge/cfs/build/cpu1/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable core-cpu1"
	cd /home/cliff/work/challenges/patch/challenge/cfs/build/cpu1/cpu1 && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/core-cpu1.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
cpu1/CMakeFiles/core-cpu1.dir/build: cpu1/core-cpu1

.PHONY : cpu1/CMakeFiles/core-cpu1.dir/build

cpu1/CMakeFiles/core-cpu1.dir/requires: cpu1/CMakeFiles/core-cpu1.dir/src/target_config.c.o.requires

.PHONY : cpu1/CMakeFiles/core-cpu1.dir/requires

cpu1/CMakeFiles/core-cpu1.dir/clean:
	cd /home/cliff/work/challenges/patch/challenge/cfs/build/cpu1/cpu1 && $(CMAKE_COMMAND) -P CMakeFiles/core-cpu1.dir/cmake_clean.cmake
.PHONY : cpu1/CMakeFiles/core-cpu1.dir/clean

cpu1/CMakeFiles/core-cpu1.dir/depend:
	cd /home/cliff/work/challenges/patch/challenge/cfs/build/cpu1 && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/cliff/work/challenges/patch/challenge/cfs/cfe /home/cliff/work/challenges/patch/challenge/cfs/cfe/cmake/target /home/cliff/work/challenges/patch/challenge/cfs/build/cpu1 /home/cliff/work/challenges/patch/challenge/cfs/build/cpu1/cpu1 /home/cliff/work/challenges/patch/challenge/cfs/build/cpu1/cpu1/CMakeFiles/core-cpu1.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : cpu1/CMakeFiles/core-cpu1.dir/depend

