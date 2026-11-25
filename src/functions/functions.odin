package functions

// -------------------------------- Imports --------------------------------

// ---------------- Odin ----------------

import "core:encoding/json"
import "core:fmt"
import "core:odin/ast"
import "core:odin/parser"
import "core:odin/tokenizer"
import "core:strconv"
import "core:strings"

// ---------------- Project ----------------

import "../state"

// -------------------------------- Constants --------------------------------

// ---------------- File ----------------

@(private = "file")
MAX_LITERALS :: 128
@(private = "file")
MAX_LITERAL_LEN :: 128
@(private = "file")
MAX_BRANCHES :: 512
@(private = "file")
MAX_BRANCH_VALUES :: 16
@(private = "file")
MAX_SCHEMAS :: 64
@(private = "file")
MAX_SCHEMA_ITEMS :: 64

// -------------------------------- Procedures --------------------------------

// ---------------- Public ----------------

// The caller owns source and parser metadata. Syntax and token scans are discovery
// evidence only; executing the compiled application establishes reachability.
inspect :: proc(text, path: string) -> state.Source {
	result := state.Source{path = path}
	file := ast.File{src = text, fullpath = path}
	p := parser.default_parser()
	p.err = parse_error
	p.warn = nil
	context.user_ptr = &result.error
	if !parser.parse_file(&p, &file) {
		if result.error == "" {result.error = "Odin parser rejected this file"}
		return result
	}
	result.package_name = file.pkg_name

	import_map := make(map[string]string)
	import_paths := make(map[string]bool)
	for imported in file.imports {
		value := imported.relpath.text
		if len(value) < 2 {continue}
		value = value[1:len(value)-1]
		name := imported.name.text
		if name == "" {
			start := 0
			for c, offset in value {
				if c == '/' || c == ':' {start = offset + 1}
			}
			name = value[start:]
		}
		append(&result.imports, state.Import{name = name, path = value})
		import_map[name] = value
		import_paths[value] = true
	}

	inspect_decls(&result, file.decls[:])
	collect_branches(&result.branches, path, file.decls[:])

	tokens: [dynamic]tokenizer.Token
	lex := tokenizer.Tokenizer{}
	tokenizer.init(&lex, text, path, nil)
	for {
		token := tokenizer.scan(&lex)
		if token.kind == .EOF {break}
		if token.kind == .File_Tag {
			tag := strings.trim_space(token.text)
			if tag == "#+ignore" || strings.has_prefix(tag, "#+ignore ") || strings.has_prefix(tag, "#+ignore\t") {
				result.ignored = true
			} else if strings.has_prefix(tag, "#+build") {
				rest := tag[len("#+build"):]
				if len(rest) == 0 || rest[0] == ' ' || rest[0] == '\t' {
					append(&result.build_tags, strings.trim_space(rest))
				}
			}
			continue
		}
		if token.kind == .Comment {continue}
		append(&tokens, token)
	}

	seen_literals := make(map[string]bool)
	seen_env := make(map[string]bool)
	seen_files := make(map[string]bool)
	seen_kinds := make(map[string]bool)

	for i := 0; i < len(tokens); i += 1 {
		tok := tokens[i]
		if tok.kind == .String {
			if value, ok := unquote_literal(tok.text); ok && len(value) > 0 && len(value) <= MAX_LITERAL_LEN {
				if !import_paths[value] && !seen_literals[value] && len(result.literals) < MAX_LITERALS {
					seen_literals[value] = true
					append(&result.literals, value)
				}
			}
		}
		if i+2 >= len(tokens) || tokens[i+1].text != "." {continue}
		pkg, imported := import_map[tok.text]
		if !imported {continue}
		member := tokens[i+2].text
		kind := ""
		if pkg == "core:os" || pkg == "core:os/os2" {
			switch member {
			case "args":
				kind = "argv"
			case "stdin":
				kind = "stdin"
			case "open", "read", "read_at_least", "read_entire_file",
			     "read_entire_file_from_filename", "read_entire_file_from_path",
			     "read_entire_file_from_handle", "read_directory",
			     "read_directory_by_path", "stat", "lstat":
				kind = "files"
			case "get_env", "lookup_env", "get_environment", "get_env_by_name":
				kind = "environment"
			case "write_entire_file", "write_entire_file_from_bytes",
			     "write_entire_file_from_string", "create", "rename", "remove", "make_directory":
				result.writes_files = true
				kind = "files"
			}
		} else if strings.has_prefix(pkg, "core:time") {
			switch member {
			case "now", "tick_now", "sleep", "since":
				kind = "clock"
			}
		} else if pkg == "core:sys/posix" {
			switch member {
			case "socket", "connect", "bind", "listen", "accept", "pipe", "mkfifo":
				kind = "ipc"
			}
		} else if pkg_kind := package_interface_kind(pkg); pkg_kind != "" {
			if pkg_kind != "ui" ||
			   strings.has_prefix(member, "IsKey") || strings.has_prefix(member, "GetKey") ||
			   strings.has_prefix(member, "GetChar") || strings.has_prefix(member, "IsMouse") ||
			   strings.has_prefix(member, "GetMouse") || strings.has_prefix(member, "IsWindow") ||
			   member == "WindowShouldClose" || member == "PollEvent" || member == "PollEvents" {
				kind = pkg_kind
			}
		}
		if kind != "" {
			seen_kinds[kind] = true
			append(&result.interfaces, state.Interface_Site{
				kind       = kind,
				path       = path,
				line       = tok.pos.line,
				expression = fmt.aprintf("%s.%s", tok.text, member),
			})
			if i+4 < len(tokens) && tokens[i+3].text == "(" && tokens[i+4].kind == .String {
				if arg_val, ok := unquote_literal(tokens[i+4].text); ok && len(arg_val) > 0 {
					if kind == "environment" && !seen_env[arg_val] {
						seen_env[arg_val] = true
						append(&result.env_names, arg_val)
					} else if kind == "files" && !seen_files[arg_val] {
						seen_files[arg_val] = true
						append(&result.filenames, arg_val)
					}
				}
			}
		}
	}

	// Imports reveal dependencies even when procedures are called through aliases.
	for imported in result.imports {
		kind := package_interface_kind(imported.path)
		if kind != "" && !seen_kinds[kind] {
			seen_kinds[kind] = true
			append(&result.interfaces, state.Interface_Site{
				kind       = kind,
				path       = path,
				line       = 1,
				expression = fmt.aprintf("import %s", imported.path),
			})
		}
	}

	return result
}

// ---------------- File ----------------

@(private = "file")
package_interface_kind :: proc(pkg: string) -> string {
	if strings.has_prefix(pkg, "core:net") {return "network"}
	if strings.contains(pkg, "raylib") || strings.contains(pkg, "sdl") || strings.contains(pkg, "glfw") {return "ui"}
	if strings.contains(pkg, "ipc") {return "ipc"}
	if strings.has_prefix(pkg, "core:math/rand") || pkg == "core:crypto" {return "randomness"}
	return ""
}

@(private = "file")
inspect_decls :: proc(result: ^state.Source, stmts: []^ast.Stmt) {
	for stmt in stmts {
		if stmt == nil {continue}
		#partial switch node in stmt.derived {
		case ^ast.Block_Stmt:
			inspect_decls(result, node.stmts[:])
		case ^ast.When_Stmt:
			if node.body != nil {inspect_decls(result, []^ast.Stmt{node.body})}
			if node.else_stmt != nil {inspect_decls(result, []^ast.Stmt{node.else_stmt})}
		case ^ast.Value_Decl:
			if node.is_mutable {continue}
			for name_expr, idx in node.names {
				ident, is_ident := name_expr.derived.(^ast.Ident)
				if !is_ident || idx >= len(node.values) || node.values[idx] == nil {continue}
				#partial switch decl in node.values[idx].derived {
				case ^ast.Proc_Lit:
					if ident.name == "main" {result.entrypoint = true}
				case ^ast.Enum_Type:
					if len(result.enums) >= MAX_SCHEMAS {continue}
					et := state.Enum_Type{name = ident.name}
					for field in decl.fields {
						if field == nil || len(et.variants) >= MAX_SCHEMA_ITEMS {break}
						if fv, ok := field.derived.(^ast.Field_Value); ok {
							if fv.field != nil {
								if v_ident, is_v := fv.field.derived.(^ast.Ident); is_v {
									append(&et.variants, v_ident.name)
								}
							}
						} else if v_ident, is_v := field.derived.(^ast.Ident); is_v {
							append(&et.variants, v_ident.name)
						}
					}
					if len(et.variants) > 0 {append(&result.enums, et)}
				case ^ast.Struct_Type:
					if len(result.structs) >= MAX_SCHEMAS || decl.fields == nil {continue}
					ss := state.Struct_Schema{name = ident.name}
					for field in decl.fields.list {
						if field == nil || len(ss.fields) >= MAX_SCHEMA_ITEMS {break}
						tname := expr_type_name(field.type)
						json_name := ""
						json_skip := false
						if tag_val, ok := unquote_literal(field.tag.text); ok {
							if pos := strings.index(tag_val, `json:"`); pos >= 0 {
								rest := tag_val[pos+6:]
								if end := strings.index_byte(rest, '"'); end >= 0 {
									spec := rest[:end]
									if comma := strings.index_byte(spec, ','); comma >= 0 {spec = spec[:comma]}
									if spec == "-" {
										json_skip = true
									} else if spec != "" {
										json_name = spec
									}
								}
							}
						}
						if json_skip {continue}
						for fname_expr in field.names {
							if len(ss.fields) >= MAX_SCHEMA_ITEMS {break}
							fident, ok := fname_expr.derived.(^ast.Ident)
							if !ok {continue}
							out_name := json_name if (json_name != "" && len(field.names) == 1) else fident.name
							append(&ss.fields, state.Struct_Field{name = out_name, type_name = tname})
						}
					}
					if len(ss.fields) > 0 {append(&result.structs, ss)}
				}
			}
		}
	}
}

@(private = "file")
expr_type_name :: proc(expr: ^ast.Expr) -> string {
	if expr == nil {return ""}
	#partial switch node in expr.derived {
	case ^ast.Ident:
		return node.name
	case ^ast.Selector_Expr:
		if node.field != nil {return node.field.name}
	case ^ast.Array_Type:
		return fmt.aprintf("[]%s", expr_type_name(node.elem))
	case ^ast.Dynamic_Array_Type:
		return fmt.aprintf("[]%s", expr_type_name(node.elem))
	case ^ast.Pointer_Type:
		return expr_type_name(node.elem)
	case ^ast.Paren_Expr:
		return expr_type_name(node.expr)
	}
	return ""
}

@(private = "file")
collect_branches :: proc(out: ^[dynamic]state.Branch_Site, path: string, stmts: []^ast.Stmt) {
	for stmt in stmts {
		if stmt == nil || len(out^) >= MAX_BRANCHES {return}
		#partial switch node in stmt.derived {
		case ^ast.Value_Decl:
			for val in node.values {
				if val == nil {continue}
				if lit, ok := val.derived.(^ast.Proc_Lit); ok && lit.body != nil {
					if block, is_blk := lit.body.derived.(^ast.Block_Stmt); is_blk {
						collect_branches(out, path, block.stmts[:])
					}
				}
			}
		case ^ast.Block_Stmt:
			collect_branches(out, path, node.stmts[:])
		case ^ast.When_Stmt:
			if node.body != nil {collect_branches(out, path, []^ast.Stmt{node.body})}
			if node.else_stmt != nil {collect_branches(out, path, []^ast.Stmt{node.else_stmt})}
		case ^ast.For_Stmt:
			if node.body != nil {collect_branches(out, path, []^ast.Stmt{node.body})}
		case ^ast.Range_Stmt:
			if node.body != nil {collect_branches(out, path, []^ast.Stmt{node.body})}
		case ^ast.Defer_Stmt:
			if node.stmt != nil {collect_branches(out, path, []^ast.Stmt{node.stmt})}
		case ^ast.If_Stmt:
			if node.body != nil && len(out^) < MAX_BRANCHES {
				bstart, bend := stmt_line_span(node.body)
				site := state.Branch_Site{
					path       = path,
					line       = node.pos.line,
					body_start = bstart,
					body_end   = bend,
					kind       = "if",
				}
				extract_expr_clues(&site, node.cond)
				append(out, site)
				collect_branches(out, path, []^ast.Stmt{node.body})
			}
			if node.else_stmt != nil && len(out^) < MAX_BRANCHES {
				if _, is_else_if := node.else_stmt.derived.(^ast.If_Stmt); !is_else_if {
					estart, eend := stmt_line_span(node.else_stmt)
					site := state.Branch_Site{
						path       = path,
						line       = node.pos.line,
						body_start = estart,
						body_end   = eend,
						kind       = "else",
					}
					extract_expr_clues(&site, node.cond)
					append(out, site)
				}
				collect_branches(out, path, []^ast.Stmt{node.else_stmt})
			}
		case ^ast.Switch_Stmt:
			if node.body != nil {
				if block, ok := node.body.derived.(^ast.Block_Stmt); ok {
					for item in block.stmts {
						if item == nil || len(out^) >= MAX_BRANCHES {break}
						clause, is_clause := item.derived.(^ast.Case_Clause)
						if !is_clause {continue}
						body_start := clause.pos.line
						body_end := clause.end.line
						if len(clause.body) > 0 {
							if clause.body[0] != nil {body_start = clause.body[0].pos.line}
							if clause.body[len(clause.body)-1] != nil {body_end = clause.body[len(clause.body)-1].end.line}
						}
						site := state.Branch_Site{
							path       = path,
							line       = node.pos.line,
							body_start = body_start,
							body_end   = body_end,
							kind       = "case",
						}
						for expr in clause.list {
							extract_expr_clues(&site, expr)
						}
						append(out, site)
						collect_branches(out, path, clause.body[:])
					}
				}
			}
		case ^ast.Type_Switch_Stmt:
			if node.body != nil {
				if block, ok := node.body.derived.(^ast.Block_Stmt); ok {
					for item in block.stmts {
						if item == nil || len(out^) >= MAX_BRANCHES {break}
						if clause, is_clause := item.derived.(^ast.Case_Clause); is_clause {
							collect_branches(out, path, clause.body[:])
						}
					}
				}
			}
		}
	}
}

@(private = "file")
stmt_line_span :: proc(stmt: ^ast.Stmt) -> (int, int) {
	start, end := stmt.pos.line, stmt.end.line
	if blk, is_blk := stmt.derived.(^ast.Block_Stmt); is_blk && len(blk.stmts) > 0 {
		if blk.stmts[0] != nil {start = blk.stmts[0].pos.line}
		if blk.stmts[len(blk.stmts)-1] != nil {end = blk.stmts[len(blk.stmts)-1].end.line}
	}
	return start, end
}

@(private = "file")
extract_expr_clues :: proc(site: ^state.Branch_Site, expr: ^ast.Expr) {
	if expr == nil {return}
	#partial switch node in expr.derived {
	case ^ast.Basic_Lit:
		if node.tok.kind == .String {
			if value, ok := unquote_literal(node.tok.text); ok && len(value) > 0 && len(value) <= MAX_LITERAL_LEN {
				append_unique(&site.strings, value, MAX_BRANCH_VALUES)
			}
		} else if node.tok.kind == .Integer {
			if num, ok := strconv.parse_i64(node.tok.text); ok {
				append_unique(&site.ints, num, MAX_BRANCH_VALUES)
			}
		}
	case ^ast.Ident:
		if len(node.name) > 0 {
			append_unique(&site.idents, node.name, MAX_BRANCH_VALUES)
		}
	case ^ast.Implicit_Selector_Expr:
		if node.field != nil {extract_expr_clues(site, node.field)}
	case ^ast.Selector_Expr:
		extract_expr_clues(site, node.expr)
		if node.field != nil {extract_expr_clues(site, node.field)}
	case ^ast.Unary_Expr:
		if node.op.text == "-" && node.expr != nil {
			if lit, ok := node.expr.derived.(^ast.Basic_Lit); ok && lit.tok.kind == .Integer {
				if num, parsed := strconv.parse_i64(lit.tok.text); parsed {
					append_unique(&site.ints, -num, MAX_BRANCH_VALUES)
					return
				}
			}
		}
		extract_expr_clues(site, node.expr)
	case ^ast.Binary_Expr:
		extract_expr_clues(site, node.left)
		extract_expr_clues(site, node.right)
	case ^ast.Paren_Expr:
		extract_expr_clues(site, node.expr)
	case ^ast.Call_Expr:
		for arg in node.args {extract_expr_clues(site, arg)}
	case ^ast.Index_Expr:
		extract_expr_clues(site, node.expr)
		extract_expr_clues(site, node.index)
	}
}

@(private = "file")
append_unique :: proc(list: ^[dynamic]$T, value: T, limit: int) {
	if len(list^) >= limit {return}
	for existing in list^ {if existing == value {return}}
	append(list, value)
}

@(private = "file")
parse_error :: proc(pos: tokenizer.Pos, message: string, args: ..any) {
	failure := cast(^string)context.user_ptr
	if failure^ == "" {
		failure^ = fmt.aprintf("%s(%d:%d): %s", pos.file, pos.line, pos.column, fmt.aprintf(message, ..args))
	}
}

@(private = "file")
unquote_literal :: proc(raw: string) -> (string, bool) {
	if len(raw) < 2 {return "", false}
	if raw[0] == '`' && raw[len(raw)-1] == '`' {
		return raw[1:len(raw)-1], true
	}
	if raw[0] == '"' && raw[len(raw)-1] == '"' {
		value: string
		if json.unmarshal(transmute([]u8)raw, &value) == nil {
			return value, true
		}
	}
	return "", false
}
