package state

// -------------------------------- Types --------------------------------

// ---------------- Public ----------------

Source :: struct {
	path:         string,
	package_name: string,
	entrypoint:   bool,
	ignored:      bool,
	writes_files: bool,
	build_tags:   [dynamic]string,
	imports:      [dynamic]Import,
	interfaces:   [dynamic]Interface_Site,
	branches:     [dynamic]Branch_Site,
	enums:        [dynamic]Enum_Type,
	structs:      [dynamic]Struct_Schema,
	literals:     [dynamic]string,
	env_names:    [dynamic]string,
	filenames:    [dynamic]string,
	error:        string,
}

Import :: struct {
	name: string,
	path: string,
}

Interface_Site :: struct {
	kind:       string,
	path:       string,
	line:       int,
	expression: string,
}

Branch_Site :: struct {
	path:       string,
	line:       int,
	body_start: int,
	body_end:   int,
	kind:       string,
	strings:    [dynamic]string,
	ints:       [dynamic]i64,
	idents:     [dynamic]string,
}

Enum_Type :: struct {
	name:     string,
	variants: [dynamic]string,
}

Struct_Schema :: struct {
	name:   string,
	fields: [dynamic]Struct_Field,
}

Struct_Field :: struct {
	name:      string,
	type_name: string,
}
