package effects

// -------------------------------- Imports --------------------------------

// ---------------- Odin ----------------

import "core:encoding/json"
import "core:fmt"
import "core:mem"
import "core:os"

// ---------------- Project ----------------

import "../functions"
import "../state"

// -------------------------------- Procedures --------------------------------

// ---------------- Public ----------------

run :: proc(paths: []string) -> int {
	metadata: mem.Dynamic_Arena
	mem.dynamic_arena_init(&metadata)
	defer mem.dynamic_arena_destroy(&metadata)
	context.allocator = mem.dynamic_arena_allocator(&metadata)
	sources: [dynamic]state.Source
	for path in paths {
		data, err := os.read_entire_file(path, context.allocator)
		if err != nil {fmt.eprintf("%s: %v\n", path, err); return 2}
		append(&sources, functions.inspect(string(data), path))
	}
	encoded, err := json.marshal(sources[:])
	if err != nil {fmt.eprintf("cannot encode discovery: %v\n", err); return 2}
	fmt.println(string(encoded))
	return 0
}
