# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import json
import os
import requests
import argparse
import logging
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=5)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

###############################################################################
# Persistent RE context helpers (local file I/O, no Ghidra endpoint needed)
###############################################################################

_EMPTY_CONTEXT = {
    "meta": {"binary_name": "", "created": "", "last_updated": "", "sessions": 0},
    "functions": {},
    "structs": {},
    "globals": {},
    "hypotheses": [],
    "next_targets": [],
    "open_threads": [],
    "dead_ends": [],
    "session_log": [],
}

def _load_context_file() -> dict:
    p = _resolve_context_path()
    if p.exists():
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    name, _ = _get_program_info()
    ctx = json.loads(json.dumps(_EMPTY_CONTEXT))  # deep copy
    ctx["meta"]["binary_name"] = name
    now = datetime.now(timezone.utc).isoformat()
    ctx["meta"]["created"] = now
    ctx["meta"]["last_updated"] = now
    return ctx

def _save_context_file(data: dict) -> None:
    data["meta"]["last_updated"] = datetime.now(timezone.utc).isoformat()
    p = _resolve_context_path()
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def _deep_merge(base: dict, update: dict) -> dict:
    for k, v in update.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        elif k in base and isinstance(base[k], list) and isinstance(v, list):
            base[k].extend(v)
        else:
            base[k] = v
    return base

def _get_program_info() -> tuple[str, str]:
    """Return (program_name, project_dir) from the running Ghidra instance."""
    lines = safe_get("programInfo")
    if len(lines) >= 2 and not lines[0].startswith("Error") and not lines[0].startswith("Request failed"):
        return lines[0].strip(), lines[1].strip()
    if len(lines) == 1 and not lines[0].startswith("Error") and not lines[0].startswith("Request failed"):
        return lines[0].strip(), ""
    return "", ""

def _resolve_context_path() -> Path:
    """Derive the context JSON path from the currently loaded Ghidra program.

    Stores the file inside the Ghidra project directory as
    <project_dir>/<program_name>.context.json.
    Falls back to ~/.ghidra_mcp/<program_name>.context.json if the project
    directory is unavailable.
    """
    name, project_dir = _get_program_info()
    if not name:
        raise RuntimeError("No program loaded in Ghidra")
    if project_dir:
        d = Path(project_dir)
    else:
        d = Path.home() / ".ghidra_mcp"
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{name}.context.json"

###############################################################################

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def search_scalars(value: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search numeric constants.
    GET /searchScalars?value=0x35
    Found 95 occurrences of scalar 0x35:
    0000c47a: addi 0x35,sp,r6  [in FUN_0000c428]
    0000c61e: st.b r11,0x35[sp]  [in FUN_0000c5b2]
    0000c67e: addi 0x35,sp,r6  [in FUN_0000c62e]
    0000c7ae: st.b r27,0x35[sp]  [in FUN_0000c758]
    0001f2ee: movea 0x35,r0,r6  [in FUN_0001f20a]
    00020308: addi 0x35,r29,r7  [in FUN_000202c6]
    000234c2: sst.b 0x35[ep],r15  [in FUN_0002340c]
    """
    if not value:
        return ["Error: value string is required"]
    return safe_get("searchScalars", {"value": value, "offset": offset, "limit": limit})

@mcp.tool()
def search_memory_by_pattern(pattern: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search numeric constants.
    GET /searchMemory?pattern=00019100
    Found 7 occurrences of pattern 00019100:
    000c1bc3 [LE]: bytes: 00 91 01 00 08 04 00 00
    000c2fc7 [LE]: bytes: 00 91 01 00 08 04 00 00
    000c733c [LE]: data: 00019100 (void *)
    001112bb [LE]: bytes: 00 91 01 00 02 FF 00 92
    0011267d [LE]: bytes: 00 91 01 00 02 FF 00 92
    00117e07 [LE]: bytes: 00 91 01 00 00 03 00 92
    00118ccb [LE]: bytes: 00 91 01 00 00 03 00 92%
    """
    if not pattern:
        return ["Error: pattern string is required"]
    return safe_get("searchMemory", {"pattern": pattern, "offset": offset, "limit": limit})


@mcp.tool()
def read_memory(address: str, length: int = 16) -> list:
    """
    Read memory in a range.
    GET /readMemory?address=0x000c735b&length=16
    Memory dump from 000c735b (16 bytes):


    000c735b:  00 CB C3 00 00 00 00 00  00 00 00 00 00 CC C3 00  |................|

    --- Interpretation ---
    As pointers (LE):
    000c735b: 0x00C3CB00
    000c735f: 0x00000000
    000c7363: 0x00000000
    000c7367: 0x00C3CC00
    """
    if not address:
        return ["Error: address string is required"]
    return safe_get("readMemory", {"address": address, "length": str(length)})


@mcp.tool()
def create_struct(name: str, fields: str) -> str:
    """
    Create a new structure data type in the program's data type manager.

    Args:
        name: Structure name (e.g., "notify_msg_envelope_t")
        fields: Comma-separated field descriptors in "name:type:size" format.
                Types: uint8_t, uint16_t, uint32_t, pointer, byte[0x4008], etc.
                Size: decimal or 0x hex.

    Example:
        create_struct(
            name="notify_msg_envelope_t",
            fields="message_type:uint32_t:4,conn_ctx:pointer:4,payload:byte[0x4008]:0x4008,data_length:uint16_t:2,_pad:uint16_t:2,client_ip:uint32_t:4"
        )
    """
    return safe_post("createStruct", {
        "name": name,
        "fields": fields
    })

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })


@mcp.tool()
def list_functions_by_refcount(limit: int = 10, order: str = "desc") -> list:
    """
    List functions sorted by their incoming reference count.
    
    This is useful for identifying:
    - Most called functions (order="desc") - often utility functions, core logic
    - Least called functions (order="asc") - potentially dead code, entry points
    
    Args:
        limit: Maximum number of functions to return (default: 10)
        order: Sort order - "desc" for most referenced first (default), 
               "asc" for least referenced first
    
    Returns:
        List of functions with their reference counts, sorted accordingly
    
    Example output:
        156 refs: memcpy @ 0x00012340
        142 refs: strlen @ 0x00012450
        98 refs: FUN_00019d62 @ 0x00019d62
        ...
    """
    return safe_get("functionsByRefCount", {"limit": str(limit), "order": order})


@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def list_functions() -> list:
    """
    List all functions in the database.
    """
    return safe_get("list_functions")

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", {"address": address})

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_data_type(address: str, new_type: str) -> str:
    """
    Set the data type at a specific address.
    
    Args:
        address: The address in hex format (e.g., "0x0000d770")
        new_type: The data type name (e.g., "int", "char *", "DWORD")
    """
    return safe_post("set_global_data_type", {
        "address": address,
        "new_type": new_type
    })

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})


@mcp.tool()
def list_strings(
    offset: int = 0, 
    limit: int = 100, 
    filter: str = None,
    min_length: int = 4,
    max_length: int = 0,
    segment: str = None,
    summary: bool = False
) -> list:
    """
    List defined strings in the program with filtering options.
    
    Designed to handle binaries with many strings efficiently by providing:
    - Pagination (offset/limit)
    - Content filtering
    - Length filtering  
    - Segment filtering
    - Summary statistics mode
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 100)
        filter: Optional substring filter (case-insensitive)
        min_length: Minimum string length to include (default: 4)
        max_length: Maximum string length (0 = no limit)
        segment: Filter by memory segment name (e.g., ".rodata", ".text")
        summary: If True, return only statistics without string list
        
    Returns:
        List of strings with addresses, or summary statistics
        
    Examples:
        # Get first 50 strings
        list_strings(limit=50)
        
        # Search for error messages
        list_strings(filter="error", limit=100)
        
        # Find long strings (potential paths, URLs)
        list_strings(min_length=50, limit=50)
        
        # Get strings from .rodata section only
        list_strings(segment=".rodata", limit=100)
        
        # Get summary statistics first
        list_strings(summary=True)
    """
    params = {
        "offset": str(offset), 
        "limit": str(limit),
        "minLength": str(min_length),
        "maxLength": str(max_length),
        "summary": "true" if summary else "false"
    }
    if filter:
        params["filter"] = filter
    if segment:
        params["segment"] = segment
        
    return safe_get("strings", params)


@mcp.tool()
def list_undefined_entries(offset: int = 0, limit: int = 100) -> list:
    """
    Find undefined entries - code that exists but is not part of any defined function.
    
    This is common in firmware where data and code are mixed together. These are
    potential functions that Ghidra's auto-analysis missed.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of entries to return (default: 100)
        
    Returns:
        List of undefined entry addresses with:
        - First instruction at the entry
        - Reference count
        - [CALL] indicator if any reference is a CALL type
        
    Example output:
        a0055700 | prepare 0x1c,0x1e                 | refs:3 [CALL]
        a0055710 | mov r1, r5                        | refs:0
        a0055718 | jr [r4]                           | refs:1
    """
    return safe_get("undefinedEntries", {"offset": str(offset), "limit": str(limit)})


@mcp.tool()
def analyze_undefined_entry(address: str, instructions: int = 15) -> str:
    """
    Analyze a single undefined entry by showing its assembly and references.
    
    Use this to inspect an entry before deciding whether to create a function.
    The assembly output lets you determine if it's valid code or data.
    
    Args:
        address: Address of the undefined entry (hex format)
        instructions: Number of instructions to disassemble (default: 15)
        
    Returns:
        - Assembly listing of the first N instructions
        - References to this address (who calls/jumps here)
        
    Example:
        analyze_undefined_entry("a0055700")
        analyze_undefined_entry("a0055700", instructions=30)
    """
    return "\n".join(safe_get("analyzeUndefinedEntry", {
        "address": address, 
        "instructions": str(instructions)
    }))


@mcp.tool()
def create_function(address: str, name: str = None) -> str:
    """
    Create a function at the specified address.
    
    Use this after analyzing an undefined entry that looks like valid function code.
    Ghidra will automatically determine the function boundaries.
    
    Args:
        address: Address where to create the function (hex format)
        name: Optional name for the function. If not provided, Ghidra
              will auto-generate a name like FUN_xxxxxxxx
              
    Returns:
        Success/failure message with function details
        
    Examples:
        create_function("a0055700")
        create_function("a0055700", "process_packet")
    """
    params = {"address": address}
    if name:
        params["name"] = name
    return safe_post("createFunction", params)


@mcp.tool()
def search_strings(query: str, limit: int = 50) -> list:
    """
    Convenience function to search for strings containing a specific substring.
    
    This is a simpler wrapper around list_strings for quick searches.
    
    Args:
        query: Substring to search for (case-insensitive)
        limit: Maximum results to return (default: 50)
        
    Returns:
        List of matching strings with their addresses
        
    Examples:
        search_strings("password")
        search_strings("http://")
        search_strings("error")
        search_strings(".dll")
    """
    return safe_get("strings", {
        "offset": "0",
        "limit": str(limit),
        "filter": query,
        "minLength": "1",
        "maxLength": "0",
        "summary": "false"
    })


@mcp.tool()
def create_segment(
    name: str,
    start: str,
    length: str,
    type: str = "RAM",
    read: bool = True,
    write: bool = True,
    execute: bool = True,
    volatile: bool = False,
    overlay: bool = False
) -> str:
    """
    Create a new memory segment/block in the program.
    
    This is useful for defining memory-mapped regions like peripheral registers,
    diagnostic RAM, or other memory areas not present in the original binary.
    
    Args:
        name: Name of the segment (e.g., "DIAG_RAM", "PERIPHERAL_REGS")
        start: Start address in hex (e.g., "0xFEBDE000")
        length: Length in hex or decimal (e.g., "0x2000" or "8192")
        type: Memory type - affects default permissions:
              - "RAM": Read/Write/Execute (default)
              - "ROM" or "FLASH": Read/Execute only
              - "CODE": Read/Write/Execute
              - "DATA": Read/Write only
        read: Read permission (default: True)
        write: Write permission (default: True, False for ROM)
        execute: Execute permission (default: True, False for DATA)
        volatile: Mark as volatile memory (default: False)
        overlay: Create as overlay block if address conflicts (default: False)
        
    Returns:
        Success message with segment details or error message
        
    Examples:
        # Create a diagnostic RAM region
        create_segment("DIAG_RAM", "0xFEBDE000", "0x2000", "RAM")
        
        # Create a peripheral register region (read/write, no execute)
        create_segment("UART_REGS", "0xF0000000", "0x100", "DATA")
        
        # Create ROM region
        create_segment("BOOTROM", "0x80000000", "0x10000", "ROM")
        
        # Create overlay if address already exists
        create_segment("DEBUG_OVERLAY", "0x00100000", "0x1000", "RAM", overlay=True)
    """
    params = {
        "name": name,
        "start": start,
        "length": length,
        "type": type,
        "read": "true" if read else "false",
        "write": "true" if write else "false",
        "execute": "true" if execute else "false",
        "volatile": "true" if volatile else "false",
        "overlay": "true" if overlay else "false"
    }
    return safe_post("createSegment", params)

###############################################################################
# Persistent RE context tools
###############################################################################

@mcp.tool()
def load_context() -> str:
    """
    Load saved reverse-engineering context for the currently loaded binary.

    The context file is stored alongside the Ghidra project. Returns the full
    JSON state (functions, structs, globals, hypotheses, next_targets,
    open_threads, dead_ends, session_log). Returns an empty skeleton if no
    context has been saved yet.
    """
    try:
        ctx = _load_context_file()
        return json.dumps(ctx, indent=2, ensure_ascii=False)
    except Exception as e:
        return f"Error loading context: {e}"


@mcp.tool()
def save_context(context: str | dict) -> str:
    """
    Persist full reverse-engineering state to disk (deep-merged with existing).

    The context file is stored alongside the Ghidra project directory.
    The context parameter is a JSON string whose keys are deep-merged into the
    existing saved state: dicts are recursively merged, lists are extended,
    and scalars are overwritten. meta.last_updated and meta.sessions are
    updated automatically.

    Args:
        context: JSON string with the state to merge
                 (e.g. '{"functions": {"main": "entry, sets up heap"}}')
    """
    try:
        update = context if isinstance(context, dict) else json.loads(context)
    except json.JSONDecodeError as e:
        return f"Error: invalid JSON — {e}"

    try:
        existing = _load_context_file()
        _deep_merge(existing, update)
        existing["meta"]["sessions"] = existing["meta"].get("sessions", 0) + 1
        name, _ = _get_program_info()
        existing["meta"]["binary_name"] = name
        _save_context_file(existing)
        return f"Context saved for '{name}' ({_resolve_context_path()})"
    except Exception as e:
        return f"Error saving context: {e}"


@mcp.tool()
def update_finding(category: str, key: str, value: str) -> str:
    """
    Upsert a single finding into the saved context for the current binary.

    For dict categories (functions, structs, globals):
        Sets context[category][key] = value.
    For list categories (hypotheses, next_targets, open_threads, dead_ends,
    session_log):
        Appends {"key": key, "value": value, "timestamp": <now>}.

    Args:
        category: Top-level key in the context schema
                  (functions | structs | globals | hypotheses | next_targets |
                   open_threads | dead_ends | session_log)
        key: The finding key (e.g. function name, struct name, hypothesis label)
        value: The finding value / description
    """
    valid = set(_EMPTY_CONTEXT.keys()) - {"meta"}
    if category not in valid:
        return f"Error: category must be one of {sorted(valid)}"

    try:
        ctx = _load_context_file()
        target = ctx.get(category)

        if isinstance(target, dict):
            ctx[category][key] = value
        elif isinstance(target, list):
            ctx[category].append({
                "key": key,
                "value": value,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        else:
            return f"Error: unexpected type for category '{category}'"

        _save_context_file(ctx)
        name, _ = _get_program_info()
        return f"Updated {category}.{key} for '{name}'"
    except Exception as e:
        return f"Error updating finding: {e}"


@mcp.tool()
def get_analysis_status() -> str:
    """
    Return a concise summary of reverse-engineering progress for the current binary.

    Shows counts of analysed functions, structs, globals, hypotheses,
    open threads, next targets, dead ends, and the last-updated timestamp.
    """
    try:
        ctx = _load_context_file()
        meta = ctx.get("meta", {})
        lines = [
            f"Binary: {meta.get('binary_name', 'unknown')}",
            f"Sessions: {meta.get('sessions', 0)}",
            f"Last updated: {meta.get('last_updated', 'never')}",
            f"Functions documented: {len(ctx.get('functions', {}))}",
            f"Structs documented: {len(ctx.get('structs', {}))}",
            f"Globals documented: {len(ctx.get('globals', {}))}",
            f"Hypotheses: {len(ctx.get('hypotheses', []))}",
            f"Open threads: {len(ctx.get('open_threads', []))}",
            f"Next targets: {len(ctx.get('next_targets', []))}",
            f"Dead ends: {len(ctx.get('dead_ends', []))}",
            f"Session log entries: {len(ctx.get('session_log', []))}",
        ]
        return "\n".join(lines)
    except Exception as e:
        return f"Error getting status: {e}"


@mcp.tool()
def set_next_targets(targets: str, notes: str = "") -> str:
    """
    Record the next functions/addresses to analyze in future sessions.

    Replaces the current next_targets list with the new set of targets.

    Args:
        targets: Comma-separated list of function names or addresses
                 (e.g. "FUN_001234,FUN_005678,process_packet")
        notes: Optional notes explaining why these targets were chosen
    """
    try:
        ctx = _load_context_file()
        now = datetime.now(timezone.utc).isoformat()
        target_list = [t.strip() for t in targets.split(",") if t.strip()]
        ctx["next_targets"] = [
            {"target": t, "notes": notes, "timestamp": now} for t in target_list
        ]
        _save_context_file(ctx)
        name, _ = _get_program_info()
        return f"Set {len(target_list)} next targets for '{name}': {', '.join(target_list)}"
    except Exception as e:
        return f"Error setting targets: {e}"


def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    
    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()

