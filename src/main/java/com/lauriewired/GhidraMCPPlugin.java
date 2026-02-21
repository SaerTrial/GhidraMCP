package com.lauriewired;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Variable;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.ClangToken;
import ghidra.framework.options.Options;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

import ghidra.program.model.mem.Memory;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.BuiltInDataTypeManager;

import ghidra.program.model.block.IsolatedEntrySubModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.app.cmd.function.CreateFunctionCmd;


@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {

    private HttpServer server;
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final int DEFAULT_PORT = 8080;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPPlugin loading...");

        // Register the configuration option
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null, // No help location for now
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");

        try {
            startServer();
        }
        catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
        Msg.info(this, "GhidraMCPPlugin loaded!");
    }

    private void startServer() throws IOException {
        // Read the configured port
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

        // Stop existing server if running (e.g., if plugin is reloaded)
        if (server != null) {
            Msg.info(this, "Stopping existing HTTP server before starting new one.");
            server.stop(0);
            server = null;
        }

        server = HttpServer.create(new InetSocketAddress(port), 0);

        // Each listing endpoint uses offset & limit from query params:
        server.createContext("/methods", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllFunctionNames(offset, limit));
        });

        server.createContext("/classes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllClassNames(offset, limit));
        });

        server.createContext("/decompile", exchange -> {
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendResponse(exchange, decompileFunctionByName(name));
        });

        server.createContext("/renameFunction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String response = renameFunction(params.get("oldName"), params.get("newName"))
                    ? "Renamed successfully" : "Rename failed";
            sendResponse(exchange, response);
        });

        server.createContext("/renameData", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            renameDataAtAddress(params.get("address"), params.get("newName"));
            sendResponse(exchange, "Rename data attempted");
        });

        server.createContext("/renameVariable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            String result = renameVariableInFunction(functionName, oldName, newName);
            sendResponse(exchange, result);
        });

        server.createContext("/segments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listSegments(offset, limit));
        });

        server.createContext("/imports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listImports(offset, limit));
        });

        server.createContext("/exports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listExports(offset, limit));
        });

        server.createContext("/namespaces", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listNamespaces(offset, limit));
        });

        server.createContext("/data", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listDefinedData(offset, limit));
        });

        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, searchFunctionsByName(searchTerm, offset, limit));
        });

        server.createContext("/searchScalars", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String scalarValue = qparams.get("value");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, searchScalars(scalarValue, offset, limit));
        });

        server.createContext("/searchMemory", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String hexPattern = qparams.get("pattern");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, searchMemoryHex(hexPattern, offset, limit));
        });

        server.createContext("/readMemory", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int length = parseIntOrDefault(qparams.get("length"), 16);
            sendResponse(exchange, readMemoryRange(address, length));
        });

        server.createContext("/createStruct", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String name = params.get("name");
            String fieldsJson = params.get("fields");
            sendResponse(exchange, createStruct(name, fieldsJson));
        });

        server.createContext("/functionsByRefCount", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int limit = parseIntOrDefault(qparams.get("limit"), 10);
            String order = qparams.get("order"); // "asc" or "desc" (default)
            sendResponse(exchange, listFunctionsByRefCount(limit, order));
        });


        // New API endpoints based on requirements
        
        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionByAddress(address));
        });

        server.createContext("/get_current_address", exchange -> {
            sendResponse(exchange, getCurrentAddress());
        });

        server.createContext("/get_current_function", exchange -> {
            sendResponse(exchange, getCurrentFunction());
        });

        server.createContext("/list_functions", exchange -> {
            sendResponse(exchange, listFunctions());
        });
        
        server.createContext("/decompile_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, decompileFunctionByAddress(address));
        });

        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, disassembleFunction(address));
        });

        server.createContext("/set_decompiler_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDecompilerComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/set_disassembly_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDisassemblyComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/rename_function_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = renameFunctionByAddress(functionAddress, newName);
            sendResponse(exchange, success ? "Function renamed successfully" : "Failed to rename function");
        });

        server.createContext("/set_function_prototype", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");

            // Call the set prototype function and get detailed result
            PrototypeResult result = setFunctionPrototype(functionAddress, prototype);

            if (result.isSuccess()) {
                // Even with successful operations, include any warning messages for debugging
                String successMsg = "Function prototype set successfully";
                if (!result.getErrorMessage().isEmpty()) {
                    successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                sendResponse(exchange, successMsg);
            } else {
                // Return the detailed error message to the client
                sendResponse(exchange, "Failed to set function prototype: " + result.getErrorMessage());
            }
        });

        server.createContext("/set_global_data_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String newType = params.get("new_type");

           // Capture detailed information about setting the type
            StringBuilder responseMsg = new StringBuilder();
            responseMsg.append("Setting variable type: ").append(newType)
                      .append(" at ").append(address).append("\n\n");

            // Attempt to find the data type in various categories
            Program program = getCurrentProgram();

            if (program != null) {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType directType = findDataTypeByNameInAllCategories(dtm, newType);
                if (directType != null) {
                    responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
                } else if (newType.startsWith("P") && newType.length() > 1) {
                    String baseTypeName = newType.substring(1);
                    DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
                    if (baseType != null) {
                        responseMsg.append("Found base type for pointer: ").append(baseType.getPathName()).append("\n");
                    } else {
                        responseMsg.append("Base type not found for pointer: ").append(baseTypeName).append("\n");
                    }
                } else {
                    responseMsg.append("Type not found directly: ").append(newType).append("\n");
                }
            }

            boolean result = setDataTypeAtAddress(address, newType);
            if (result) {
                sendResponse(exchange, responseMsg + "Data type set successfully");
            } else {
                sendResponse(exchange, responseMsg + "Failed to set data type");
            }
        });

        server.createContext("/undefinedEntries", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, findUndefinedEntries(offset, limit));
        });

        server.createContext("/createFunction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String name = params.get("name"); // optional function name
            sendResponse(exchange, createFunctionAtAddress(address, name));
        });

        server.createContext("/analyzeUndefinedEntry", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int instrCount = parseIntOrDefault(qparams.get("instructions"), 15);
            sendResponse(exchange, analyzeUndefinedEntry(address, instrCount));
        });

        server.createContext("/set_local_variable_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");

            // Capture detailed information about setting the type
            StringBuilder responseMsg = new StringBuilder();
            responseMsg.append("Setting variable type: ").append(variableName)
                      .append(" to ").append(newType)
                      .append(" in function at ").append(functionAddress).append("\n\n");

            // Attempt to find the data type in various categories
            Program program = getCurrentProgram();
            if (program != null) {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType directType = findDataTypeByNameInAllCategories(dtm, newType);
                if (directType != null) {
                    responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
                } else if (newType.startsWith("P") && newType.length() > 1) {
                    String baseTypeName = newType.substring(1);
                    DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
                    if (baseType != null) {
                        responseMsg.append("Found base type for pointer: ").append(baseType.getPathName()).append("\n");
                    } else {
                        responseMsg.append("Base type not found for pointer: ").append(baseTypeName).append("\n");
                    }
                } else {
                    responseMsg.append("Type not found directly: ").append(newType).append("\n");
                }
            }

            // Try to set the type
            boolean success = setLocalVariableType(functionAddress, variableName, newType);

            String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
            responseMsg.append("\nResult: ").append(successMsg);

            sendResponse(exchange, responseMsg.toString());
        });


        server.createContext("/createSegment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String name = params.get("name");
            String start = params.get("start");
            String length = params.get("length");
            String type = params.get("type"); // RAM, ROM, or other
            boolean read = !"false".equalsIgnoreCase(params.get("read"));
            boolean write = !"false".equalsIgnoreCase(params.get("write"));
            boolean execute = !"false".equalsIgnoreCase(params.get("execute"));
            boolean volatileMem = "true".equalsIgnoreCase(params.get("volatile"));
            boolean overlay = "true".equalsIgnoreCase(params.get("overlay"));
            sendResponse(exchange, createMemorySegment(name, start, length, type, read, write, execute, volatileMem, overlay));
        });

        server.createContext("/xrefs_to", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsTo(address, offset, limit));
        });

        server.createContext("/xrefs_from", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsFrom(address, offset, limit));
        });

        server.createContext("/function_xrefs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getFunctionXrefs(name, offset, limit));
        });

        server.createContext("/strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            int minLength = parseIntOrDefault(qparams.get("minLength"), 4);
            int maxLength = parseIntOrDefault(qparams.get("maxLength"), 0); // 0 = no max
            String segment = qparams.get("segment"); // filter by memory segment
            boolean summary = "true".equalsIgnoreCase(qparams.get("summary")); // just return stats
            
            sendResponse(exchange, listDefinedStrings(offset, limit, filter, minLength, maxLength, segment, summary));
        });

        server.setExecutor(null);
        new Thread(() -> {
            try {
                server.start();
                Msg.info(this, "GhidraMCP HTTP server started on port " + port);
            } catch (Exception e) {
                Msg.error(this, "Failed to start HTTP server on port " + port + ". Port might be in use.", e);
                server = null; // Ensure server isn't considered running
            }
        }, "GhidraMCP-HTTP-Server").start();
    }

    // ----------------------------------------------------------------------------------
    // Pagination-aware listing methods
    // ----------------------------------------------------------------------------------

    private String getAllFunctionNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return paginateList(names, offset, limit);
    }

    private String getAllClassNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        // Convert set to list for pagination
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listSegments(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }

    private String listImports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return paginateList(lines, offset, limit);
    }

    private String listExports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            // On older Ghidra, "export" is recognized via isExternalEntryPoint()
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String listNamespaces(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listDefinedData(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label   = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s",
                        data.getAddress(),
                        escapeNonAscii(label),
                        escapeNonAscii(valRepr)
                    ));
                }
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String searchFunctionsByName(String searchTerm, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";
    
        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            // simple substring match
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }
    
        Collections.sort(matches);
    
        if (matches.isEmpty()) {
            return "No functions matching '" + searchTerm + "'";
        }
        return paginateList(matches, offset, limit);
    }    

/**
     * Search for scalar (constant) values in instructions throughout the program.
     * Scalars are numeric constants used as operands in instructions.
     * 
     * @param scalarValueStr The scalar value to search for (decimal or hex with 0x prefix)
     * @param offset Pagination offset
     * @param limit Maximum number of results to return
     * @return Formatted string of locations where the scalar is found
     */
    private String searchScalars(String scalarValueStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (scalarValueStr == null || scalarValueStr.isEmpty()) return "Scalar value is required";

        long scalarValue;
        try {
            // Support both decimal and hex (0x prefix) formats
            if (scalarValueStr.toLowerCase().startsWith("0x")) {
                scalarValue = Long.parseUnsignedLong(scalarValueStr.substring(2), 16);
            } else {
                scalarValue = Long.parseLong(scalarValueStr);
            }
        } catch (NumberFormatException e) {
            return "Invalid scalar value: " + scalarValueStr + ". Use decimal or hex (0x) format.";
        }

        List<String> matches = new ArrayList<>();
        Listing listing = program.getListing();
        InstructionIterator instructions = listing.getInstructions(true);

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            
            // Check each operand for scalar values
            int numOperands = instr.getNumOperands();
            for (int i = 0; i < numOperands; i++) {
                // Get scalar from operand if present
                ghidra.program.model.scalar.Scalar scalar = instr.getScalar(i);
                if (scalar != null) {
                    // Check both signed and unsigned values
                    if (scalar.getValue() == scalarValue || scalar.getUnsignedValue() == scalarValue) {
                        // Get containing function if available
                        Function func = program.getFunctionManager().getFunctionContaining(instr.getAddress());
                        String funcName = (func != null) ? func.getName() : "<no function>";
                        
                        matches.add(String.format("%s: %s  [in %s]",
                            instr.getAddress(),
                            instr.toString(),
                            funcName));
                    }
                }
            }
        }

        if (matches.isEmpty()) {
            return "No instructions found containing scalar value: " + scalarValueStr;
        }

        return String.format("Found %d occurrences of scalar %s:\n%s", 
            matches.size(), 
            scalarValueStr,
            paginateList(matches, offset, limit));
    }    

   /**
     * Search memory for a hex byte pattern.
     * Useful for finding function tables, data references not captured by xrefs, etc.
     * 
     * @param hexPattern Hex string to search for. Formats supported:
     *                   - Address format: "00019100" (will be converted to little-endian bytes)
     *                   - Raw bytes: "00 91 01 00" or "00910100"
     *                   - With 0x prefix: "0x00019100"
     * @param offset Pagination offset
     * @param limit Maximum number of results to return
     * @return Formatted string of memory locations where the pattern is found
     */
    private String searchMemoryHex(String hexPattern, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (hexPattern == null || hexPattern.isEmpty()) return "Hex pattern is required";

        // Clean up the hex pattern - remove spaces, 0x prefix
        String cleanedPattern = hexPattern.trim()
            .replaceAll("\\s+", "")
            .replaceAll("^0[xX]", "");

        // Validate hex string
        if (!cleanedPattern.matches("[0-9a-fA-F]+")) {
            return "Invalid hex pattern. Use format: '00019100', '0x00019100', or '00 91 01 00'";
        }

        // Ensure even number of hex digits
        if (cleanedPattern.length() % 2 != 0) {
            cleanedPattern = "0" + cleanedPattern;
        }

        // Convert hex string to byte array
        byte[] searchBytes = hexStringToBytes(cleanedPattern);
        if (searchBytes == null || searchBytes.length == 0) {
            return "Failed to parse hex pattern";
        }

        // Also create little-endian version for address searches
        byte[] searchBytesLE = reverseBytesArray(searchBytes);

        List<String> matches = new ArrayList<>();
        Memory memory = program.getMemory();

        // Search through all memory blocks
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized()) continue;

            Address start = block.getStart();
            Address end = block.getEnd();

            // Search for big-endian pattern
            Address found = searchInRange(memory, start, end, searchBytes);
            while (found != null) {
                matches.add(formatMemoryMatch(program, found, searchBytes, "BE"));
                // Continue search after found address
                Address nextStart = found.add(1);
                if (nextStart.compareTo(end) <= 0) {
                    found = searchInRange(memory, nextStart, end, searchBytes);
                } else {
                    break;
                }
            }

            // Search for little-endian pattern (if different from BE)
            if (!Arrays.equals(searchBytes, searchBytesLE)) {
                found = searchInRange(memory, start, end, searchBytesLE);
                while (found != null) {
                    matches.add(formatMemoryMatch(program, found, searchBytesLE, "LE"));
                    Address nextStart = found.add(1);
                    if (nextStart.compareTo(end) <= 0) {
                        found = searchInRange(memory, nextStart, end, searchBytesLE);
                    } else {
                        break;
                    }
                }
            }
        }

        // Remove duplicates and sort
        List<String> uniqueMatches = new ArrayList<>(new LinkedHashSet<>(matches));
        Collections.sort(uniqueMatches);

        if (uniqueMatches.isEmpty()) {
            return String.format("No matches found for pattern: %s\n" +
                "Searched for bytes (BE): %s\n" +
                "Searched for bytes (LE): %s",
                hexPattern,
                bytesToHexString(searchBytes),
                bytesToHexString(searchBytesLE));
        }

        return String.format("Found %d occurrences of pattern %s:\n%s",
            uniqueMatches.size(),
            hexPattern,
            paginateList(uniqueMatches, offset, limit));
    }

    /**
     * Search for byte pattern in a memory range
     */
    private Address searchInRange(Memory memory, Address start, Address end, byte[] pattern) {
        try {
            return memory.findBytes(start, end, pattern, null, true, null);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Format a memory match result with context information
     */
    private String formatMemoryMatch(Program program, Address addr, byte[] pattern, String endianness) {
        StringBuilder result = new StringBuilder();
        result.append(String.format("%s [%s]: ", addr, endianness));

        // Check if this is in a function
        Function func = program.getFunctionManager().getFunctionContaining(addr);
        if (func != null) {
            result.append(String.format("in function %s, ", func.getName()));
        }

        // Check what's at this address
        Listing listing = program.getListing();
        Data data = listing.getDataAt(addr);
        if (data != null) {
            result.append(String.format("data: %s (%s)", data.getDefaultValueRepresentation(), data.getDataType().getName()));
        } else {
            Instruction instr = listing.getInstructionAt(addr);
            if (instr != null) {
                result.append(String.format("instruction: %s", instr.toString()));
            } else {
                // Show raw bytes at location
                result.append("bytes: ");
                try {
                    byte[] context = new byte[Math.min(8, pattern.length + 4)];
                    program.getMemory().getBytes(addr, context);
                    result.append(bytesToHexString(context));
                } catch (Exception e) {
                    result.append(bytesToHexString(pattern));
                }
            }
        }

        // Check for any labels/symbols at this address
        Symbol[] symbols = program.getSymbolTable().getSymbols(addr);
        if (symbols.length > 0) {
            result.append(String.format(" [label: %s]", symbols[0].getName()));
        }

        return result.toString();
    }

    /**
     * Convert hex string to byte array
     */
    private byte[] hexStringToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Reverse byte array (for endianness conversion)
     */
    private byte[] reverseBytesArray(byte[] bytes) {
        byte[] reversed = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            reversed[i] = bytes[bytes.length - 1 - i];
        }
        return reversed;
    }

    /**
     * Convert byte array to hex string for display
     */
    private String bytesToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) sb.append(" ");
            sb.append(String.format("%02X", bytes[i] & 0xFF));
        }
        return sb.toString();
    }

    /**
     * Read a range of memory bytes from a specified address.
     * Returns hex dump with ASCII representation.
     * Respects the program's endianness when interpreting pointer values.
     * 
     * @param addressStr Starting address (hex with optional 0x prefix)
     * @param length Number of bytes to read (default 16, max 4096)
     * @return Formatted hex dump of the memory range
     */
    private String readMemoryRange(String addressStr, int length) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        // Limit length to prevent huge responses
        int maxLength = 4096;
        if (length <= 0) length = 16;
        if (length > maxLength) length = maxLength;

        try {
            Address startAddr = program.getAddressFactory().getAddress(addressStr);
            if (startAddr == null) {
                return "Invalid address: " + addressStr;
            }

            ghidra.program.model.mem.Memory memory = program.getMemory();
            
            // Check if address is in valid memory
            if (!memory.contains(startAddr)) {
                return "Address " + addressStr + " is not in valid memory";
            }

            // Get the program's endianness
            boolean isBigEndian = program.getLanguage().isBigEndian();
            String endianStr = isBigEndian ? "BE" : "LE";

            // Read the bytes
            byte[] bytes = new byte[length];
            int bytesRead = memory.getBytes(startAddr, bytes, 0, length);
            
            if (bytesRead <= 0) {
                return "Could not read memory at " + addressStr;
            }

            // Format as hex dump
            StringBuilder result = new StringBuilder();
            result.append(String.format("Memory dump from %s (%d bytes, %s):\n\n", 
                startAddr, bytesRead, endianStr));

            // Add context info
            Function func = program.getFunctionManager().getFunctionContaining(startAddr);
            if (func != null) {
                result.append(String.format("In function: %s\n", func.getName()));
            }
            Symbol[] symbols = program.getSymbolTable().getSymbols(startAddr);
            if (symbols.length > 0) {
                result.append(String.format("Label: %s\n", symbols[0].getName()));
            }
            result.append("\n");

            // Hex dump with 16 bytes per line
            int bytesPerLine = 16;
            for (int i = 0; i < bytesRead; i += bytesPerLine) {
                Address lineAddr = startAddr.add(i);
                
                // Address column
                result.append(String.format("%s:  ", lineAddr));

                // Hex bytes
                StringBuilder hexPart = new StringBuilder();
                StringBuilder asciiPart = new StringBuilder();
                
                for (int j = 0; j < bytesPerLine; j++) {
                    if (i + j < bytesRead) {
                        byte b = bytes[i + j];
                        hexPart.append(String.format("%02X ", b & 0xFF));
                        
                        // ASCII representation (printable chars only)
                        if (b >= 32 && b < 127) {
                            asciiPart.append((char) b);
                        } else {
                            asciiPart.append('.');
                        }
                    } else {
                        hexPart.append("   ");
                        asciiPart.append(' ');
                    }
                    
                    // Add extra space in middle for readability
                    if (j == 7) {
                        hexPart.append(" ");
                    }
                }

                result.append(hexPart);
                result.append(" |");
                result.append(asciiPart);
                result.append("|\n");
            }

            // Add interpretation hints
            result.append("\n--- Interpretation ---\n");
            
            // Show as potential addresses (respecting program endianness)
            int pointerSize = program.getDefaultPointerSize();
            if (bytesRead >= pointerSize) {
                result.append(String.format("As pointers (%s):\n", endianStr));
                for (int i = 0; i <= bytesRead - pointerSize; i += pointerSize) {
                    long value = 0;
                    
                    if (isBigEndian) {
                        // Big-endian: MSB first
                        for (int j = 0; j < pointerSize; j++) {
                            value = (value << 8) | (bytes[i + j] & 0xFF);
                        }
                    } else {
                        // Little-endian: LSB first
                        for (int j = 0; j < pointerSize; j++) {
                            value |= ((long)(bytes[i + j] & 0xFF)) << (j * 8);
                        }
                    }
                    
                    Address ptrAddr = startAddr.add(i);
                    String ptrStr = String.format(pointerSize == 4 ? "%08X" : "%016X", value);
                    
                    // Check if this points to a known function or symbol
                    Address targetAddr = program.getAddressFactory().getAddress(ptrStr);
                    String targetInfo = "";
                    if (targetAddr != null) {
                        Function targetFunc = program.getFunctionManager().getFunctionAt(targetAddr);
                        if (targetFunc != null) {
                            targetInfo = " -> " + targetFunc.getName();
                        } else {
                            Symbol[] targetSyms = program.getSymbolTable().getSymbols(targetAddr);
                            if (targetSyms.length > 0) {
                                targetInfo = " -> " + targetSyms[0].getName();
                            }
                        }
                    }
                    result.append(String.format("  %s: 0x%s%s\n", ptrAddr, ptrStr, targetInfo));
                }
            }

            return result.toString();

        } catch (Exception e) {
            return "Error reading memory: " + e.getMessage();
        }
    }


    // ----------------------------------------------------------------------------------
    // Logic for rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    private String decompileFunctionByName(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result =
                    decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return result.getDecompiledFunction().getC();
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }

    private boolean renameFunction(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename function via HTTP");
                try {
                    for (Function func : program.getFunctionManager().getFunctions(true)) {
                        if (func.getName().equals(oldName)) {
                            func.setName(newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                            break;
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, successFlag.get()));
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }
        return successFlag.get();
    }

    private void renameDataAtAddress(String addressStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return;

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    Listing listing = program.getListing();
                    Data data = listing.getDefinedDataAt(addr);
                    if (data != null) {
                        SymbolTable symTable = program.getSymbolTable();
                        Symbol symbol = symTable.getPrimarySymbol(addr);
                        if (symbol != null) {
                            symbol.setName(newName, SourceType.USER_DEFINED);
                        } else {
                            symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Rename data error", e);
                }
                finally {
                    program.endTransaction(tx, true);
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
        }
    }

    private String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return "Function not found";
        }

        DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        HighFunction highFunction = result.getHighFunction();
        if (highFunction == null) {
            return "Decompilation failed (no high function)";
        }

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return "Decompilation failed (no local symbol map)";
        }

        HighSymbol highSymbol = null;
        Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            String symbolName = symbol.getName();
            
            if (symbolName.equals(oldVarName)) {
                highSymbol = symbol;
            }
            if (symbolName.equals(newVarName)) {
                return "Error: A variable with name '" + newVarName + "' already exists in this function";
            }
        }

        if (highSymbol == null) {
            return "Variable not found";
        }

        boolean commitRequired = checkFullCommit(highSymbol, highFunction);

        final HighSymbol finalHighSymbol = highSymbol;
        final Function finalFunction = func;
        AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {           
                int tx = program.startTransaction("Rename variable");
                try {
                    if (commitRequired) {
                        HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                            ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
                    }
                    HighFunctionDBUtil.updateDBVariable(
                        finalHighSymbol,
                        newVarName,
                        null,
                        SourceType.USER_DEFINED
                    );
                    successFlag.set(true);
                }
                catch (Exception e) {
                    Msg.error(this, "Failed to rename variable", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, true));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }
        return successFlag.get() ? "Variable renamed" : "Failed to rename variable";
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
	 * Compare the given HighFunction's idea of the prototype with the Function's idea.
	 * Return true if there is a difference. If a specific symbol is being changed,
	 * it can be passed in to check whether or not the prototype is being affected.
	 * @param highSymbol (if not null) is the symbol being modified
	 * @param hfunction is the given HighFunction
	 * @return true if there is a difference (and a full commit is required)
	 */
	protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
			return false;
		}
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}

		for (int i = 0; i < numParams; i++) {
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			VariableStorage storage = param.getStorage();
			// Don't compare using the equals method so that DynamicVariableStorage can match
			if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}

		return false;
	}

    // ----------------------------------------------------------------------------------
    // New methods to implement the new functionalities
    // ----------------------------------------------------------------------------------

    /**
     * Get function by address
     */
    private String getFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);

            if (func == null) return "No function found at address " + addressStr;

            return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                func.getName(),
                func.getEntryPoint(),
                func.getSignature(),
                func.getEntryPoint(),
                func.getBody().getMinAddress(),
                func.getBody().getMaxAddress());
        } catch (Exception e) {
            return "Error getting function: " + e.getMessage();
        }
    }

    /**
     * Get current address selected in Ghidra GUI
     */
    private String getCurrentAddress() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }

    /**
     * Get current function selected in Ghidra GUI
     */
    private String getCurrentFunction() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return "No current location";

        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return "No function at current location: " + location.getAddress();

        return String.format("Function: %s at %s\nSignature: %s",
            func.getName(),
            func.getEntryPoint(),
            func.getSignature());
    }

    /**
     * List all functions in the database
     */
    private String listFunctions() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        StringBuilder result = new StringBuilder();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            result.append(String.format("%s at %s\n", 
                func.getName(), 
                func.getEntryPoint()));
        }

        return result.toString();
    }

    /**
     * Gets a function at the given address or containing the address
     * @return the function or null if not found
     */
    private Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    /**
     * Decompile a function at the given address
     */
    private String decompileFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());

            return (result != null && result.decompileCompleted()) 
                ? result.getDecompiledFunction().getC() 
                : "Decompilation failed";
        } catch (Exception e) {
            return "Error decompiling function: " + e.getMessage();
        }
    }

    /**
     * Get assembly code for a function
     */
    private String disassembleFunction(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            StringBuilder result = new StringBuilder();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break; // Stop if we've gone past the end of the function
                }
                String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";

                result.append(String.format("%s: %s %s\n", 
                    instr.getAddress(), 
                    instr.toString(),
                    comment));
            }

            return result.toString();
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }    

    /**
     * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT)
     */
    private boolean setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (addressStr == null || addressStr.isEmpty() || comment == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    success.set(program.endTransaction(tx, success.get()));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Set a comment for a given address in the function pseudocode
     */
    private boolean setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    /**
     * Set a comment for a given address in the function disassembly
     */
    private boolean setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    /**
     * Class to hold the result of a prototype setting operation
     */
    private static class PrototypeResult {
        private final boolean success;
        private final String errorMessage;

        public PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    private void _setDataTypeAtAddress(String addressStr, String dataTypeName) {
        Program program = getCurrentProgram();
        int tx = program.startTransaction("Change Global Data Type");

        Address addr = program.getAddressFactory().getAddress(addressStr);
        DataTypeManager dtm = program.getDataTypeManager();
        final StringBuilder errorMessage = new StringBuilder();

        // Find the data type
        
        DataType dataType = resolveDataType(dtm, dataTypeName);
        if (dataType == null) {
            errorMessage.append("Could not find data type: " + dataTypeName);
            return;
        }
        
        // Clear existing data at address
        Listing listing = program.getListing();
        listing.clearCodeUnits(addr, addr.add(dataType.getLength() - 1), false);

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            listing.createData(addr, dataType);
            success.set(true);
        } catch (Exception e) {
            errorMessage.append("Failed to create data: " + e.getMessage());
        } finally {
            program.endTransaction(tx, success.get());
        }
    }



    private boolean setDataTypeAtAddress(String addressStr, String dataTypeName) {
        Program program = getCurrentProgram();
        if (program == null) {
            return false;
        }
        if (addressStr == null || addressStr.isEmpty()) {
            return false;
        }
        if (dataTypeName == null || dataTypeName.isEmpty()) {
            return false;
        }
        
        final StringBuilder errorMessage = new StringBuilder();
        
        try {
            SwingUtilities.invokeAndWait(() -> {
                _setDataTypeAtAddress(addressStr, dataTypeName);
            });
        } catch (InterruptedException | InvocationTargetException e) {
            errorMessage.append("Swing thread error: " + e.getMessage());
        }
        
        return true;
    }

    /**
     * Rename a function by its address
     */
    private boolean renameFunctionByAddress(String functionAddrStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            newName == null || newName.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                performFunctionRename(program, functionAddrStr, newName, success);
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename function on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method to perform the actual function rename within a transaction
     */
    private void performFunctionRename(Program program, String functionAddrStr, String newName, AtomicBoolean success) {
        int tx = program.startTransaction("Rename function by address");
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            func.setName(newName, SourceType.USER_DEFINED);
            success.set(true);
        } catch (Exception e) {
            Msg.error(this, "Error renaming function by address", e);
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd
     */
    private PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyFunctionPrototype(program, functionAddrStr, prototype, success, errorMessage));
        } catch (InterruptedException | InvocationTargetException e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        return new PrototypeResult(success.get(), errorMessage.toString());
    }

    /**
     * Helper method that applies the function prototype within a transaction
     */
    private void applyFunctionPrototype(Program program, String functionAddrStr, String prototype, 
                                       AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);

            // Store original prototype as a comment for reference
            addPrototypeComment(program, func, prototype);

            // Use ApplyFunctionSignatureCmd to parse and apply the signature
            parseFunctionSignatureAndApply(program, addr, prototype, success, errorMessage);

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }

    /**
     * Add a comment showing the prototype being set
     */
    private void addPrototypeComment(Program program, Function func, String prototype) {
        int txComment = program.startTransaction("Add prototype comment");
        try {
            program.getListing().setComment(
                func.getEntryPoint(), 
                CodeUnit.PLATE_COMMENT, 
                "Setting prototype: " + prototype
            );
        } finally {
            program.endTransaction(txComment, true);
        }
    }

    /**
     * Parse and apply the function signature with error handling
     */
    private void parseFunctionSignatureAndApply(Program program, Address addr, String prototype,
                                              AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Get data type manager service
            ghidra.app.services.DataTypeManagerService dtms = 
                tool.getService(ghidra.app.services.DataTypeManagerService.class);

            // Create function signature parser
            ghidra.app.util.parser.FunctionSignatureParser parser = 
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

            // Parse the prototype into a function signature
            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                String msg = "Failed to parse function prototype";
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            // Create and apply the command
            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd = 
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                    addr, sig, SourceType.USER_DEFINED);

            // Apply the command to the program
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                success.set(true);
                Msg.info(this, "Successfully applied function signature");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                errorMessage.append(msg);
                Msg.error(this, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, success.get());
        }
    }

    /**
     * Set a local variable's type using HighFunctionDBUtil.updateDBVariable
     */
    private boolean setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            variableName == null || variableName.isEmpty() ||
            newType == null || newType.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyVariableType(program, functionAddrStr, variableName, newType, success));
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }

        return success.get();
    }

    /**
     * List functions sorted by their incoming reference count.
     * 
     * @param limit Maximum number of functions to return (default: 10)
     * @param order Sort order: "asc" for ascending, "desc" for descending (default)
     * @return Formatted string of functions with their reference counts
     */
    private String listFunctionsByRefCount(int limit, String order) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        FunctionManager funcManager = program.getFunctionManager();
        ReferenceManager refManager = program.getReferenceManager();

        // Build a list of (function, refCount) pairs
        List<Map.Entry<Function, Integer>> functionRefCounts = new ArrayList<>();

        for (Function func : funcManager.getFunctions(true)) {
            Address entryPoint = func.getEntryPoint();
            int refCount = refManager.getReferenceCountTo(entryPoint);
            functionRefCounts.add(new AbstractMap.SimpleEntry<>(func, refCount));
        }

        // Sort by reference count
        boolean ascending = "asc".equalsIgnoreCase(order);
        functionRefCounts.sort((a, b) -> {
            int cmp = Integer.compare(a.getValue(), b.getValue());
            return ascending ? cmp : -cmp;
        });

        // Build output
        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (Map.Entry<Function, Integer> entry : functionRefCounts) {
            if (count >= limit) break;
            
            Function func = entry.getKey();
            int refCount = entry.getValue();
            
            sb.append(String.format("%d refs: %s @ %s\n", 
                refCount, 
                func.getName(), 
                func.getEntryPoint()));
            count++;
        }

        if (sb.length() == 0) {
            return "No functions found";
        }

        return sb.toString().trim();
    }



    /**
     * Helper method that performs the actual variable type change
     */
    private void applyVariableType(Program program, String functionAddrStr, 
                                  String variableName, String newType, AtomicBoolean success) {
        try {
            // Find the function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            DecompileResults results = decompileFunction(func, program);
            if (results == null || !results.decompileCompleted()) {
                return;
            }

            ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                Msg.error(this, "No high function available");
                return;
            }

            // Find the symbol by name
            HighSymbol symbol = findSymbolByName(highFunction, variableName);
            if (symbol == null) {
                Msg.error(this, "Could not find variable '" + variableName + "' in decompiled function");
                return;
            }

            // Get high variable
            HighVariable highVar = symbol.getHighVariable();
            if (highVar == null) {
                Msg.error(this, "No HighVariable found for symbol: " + variableName);
                return;
            }

            Msg.info(this, "Found high variable for: " + variableName + 
                     " with current type " + highVar.getDataType().getName());

            // Find the data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newType);

            if (dataType == null) {
                Msg.error(this, "Could not resolve data type: " + newType);
                return;
            }

            Msg.info(this, "Using data type: " + dataType.getName() + " for variable " + variableName);

            // Apply the type change in a transaction
            updateVariableType(program, symbol, dataType, success);

        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        }
    }

    /**
     * Find a high symbol by name in the given high function
     */
    private HighSymbol findSymbolByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    /**
     * Find undefined entries - code that exists but is not part of any defined function.
     * This is common in firmware where data and code are mixed.
     */
    private String findUndefinedEntries(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        try {
            Listing listing = program.getListing();
            Memory memory = program.getMemory();
            ReferenceManager refManager = program.getReferenceManager();
            
            // Build address set of all instructions
            AddressSet instructionSet = new AddressSet();
            InstructionIterator instrIter = listing.getInstructions(memory, true);
            while (instrIter.hasNext()) {
                Instruction instr = instrIter.next();
                instructionSet.addRange(instr.getMinAddress(), instr.getMaxAddress());
            }
            
            // Remove addresses that are inside defined functions
            FunctionIterator funcIter = listing.getFunctions(true);
            while (funcIter.hasNext()) {
                Function func = funcIter.next();
                instructionSet.delete(func.getBody());
            }
            
            if (instructionSet.getNumAddressRanges() == 0) {
                return "No undefined entries found - all instructions are contained inside functions";
            }
            
            // Find entry points of isolated code blocks
            ghidra.program.model.block.IsolatedEntrySubModel submodel = 
                new ghidra.program.model.block.IsolatedEntrySubModel(program);
            ghidra.program.model.block.CodeBlockIterator blockIter = 
                submodel.getCodeBlocksContaining(instructionSet, new ConsoleTaskMonitor());
            
            // Collect unique start addresses
            Set<Address> codeStarts = new LinkedHashSet<>();
            while (blockIter.hasNext()) {
                ghidra.program.model.block.CodeBlock block = blockIter.next();
                Address start = block.getFirstStartAddress();
                codeStarts.add(start);
            }
            
            List<String> results = new ArrayList<>();
            int totalEntries = codeStarts.size();
            
            // Add summary header
            results.add(String.format("Found %d undefined entries\n", totalEntries));
            
            int index = 0;
            for (Address addr : codeStarts) {
                if (index < offset) {
                    index++;
                    continue;
                }
                if (index >= offset + limit) {
                    break;
                }
                
                // Get first instruction
                Instruction instr = listing.getInstructionAt(addr);
                String instrStr = instr != null ? instr.toString() : "??";
                
                // Count references
                int refCount = refManager.getReferenceCountTo(addr);
                
                // Check for CALL references
                boolean hasCallRef = false;
                ReferenceIterator refIter = refManager.getReferencesTo(addr);
                while (refIter.hasNext()) {
                    Reference ref = refIter.next();
                    if (ref.getReferenceType().isCall()) {
                        hasCallRef = true;
                        break;
                    }
                }
                
                // Format: address | instruction | refs | call indicator
                String callIndicator = hasCallRef ? " [CALL]" : "";
                results.add(String.format("%s | %-30s | refs:%d%s", 
                    addr, instrStr, refCount, callIndicator));
                
                index++;
            }
            
            // Add pagination info
            results.add(String.format("\nShowing %d-%d of %d", 
                Math.min(offset + 1, totalEntries),
                Math.min(offset + limit, totalEntries),
                totalEntries));
            
            return String.join("\n", results);
            
        } catch (Exception e) {
            return "Error finding undefined entries: " + e.getMessage();
        }
    }

    /**
     * Analyze a single undefined entry by showing its assembly and references.
     * Let the LLM determine if it's a valid function based on the instructions.
     */
    private String analyzeUndefinedEntry(String addressStr, int instrCount) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "Invalid address: " + addressStr;
            
            Listing listing = program.getListing();
            ReferenceManager refManager = program.getReferenceManager();
            
            StringBuilder result = new StringBuilder();
            result.append(String.format("=== Undefined entry at %s ===\n\n", addr));
            
            // Check if already a function
            Function existingFunc = program.getFunctionManager().getFunctionAt(addr);
            if (existingFunc != null) {
                result.append(String.format("Already defined as function: %s\n", existingFunc.getName()));
                return result.toString();
            }
            
            // Check if there's an instruction
            Instruction firstInstr = listing.getInstructionAt(addr);
            if (firstInstr == null) {
                result.append("No instruction at this address - this is data, not code.\n");
                return result.toString();
            }
            
            // Show assembly instructions
            result.append(String.format("Assembly (%d instructions):\n", instrCount));
            Address currentAddr = addr;
            Set<Address> visited = new HashSet<>();
            int count = 0;
            
            while (count < instrCount && currentAddr != null && !visited.contains(currentAddr)) {
                visited.add(currentAddr);
                Instruction instr = listing.getInstructionAt(currentAddr);
                if (instr == null) break;
                
                result.append(String.format("  %s: %s\n", currentAddr, instr.toString()));
                count++;
                
                // Follow flow
                currentAddr = instr.getFallThrough();
                if (currentAddr == null) {
                    // Check for unconditional jump
                    FlowType flowType = instr.getFlowType();
                    if (flowType.isJump() && !flowType.isConditional()) {
                        Address[] flows = instr.getFlows();
                        if (flows.length > 0) {
                            currentAddr = flows[0];
                        }
                    }
                }
            }
            
            // Show references TO this address
            result.append("\nReferences to this address:\n");
            ReferenceIterator refsToIter = refManager.getReferencesTo(addr);
            List<Reference> refsTo = new ArrayList<>();
            while (refsToIter.hasNext()) {
                refsTo.add(refsToIter.next());
            }
            if (refsTo.isEmpty()) {
                result.append("  (none)\n");
            } else {
                int refCount = 0;
                for (Reference ref : refsTo) {
                    if (refCount >= 10) {
                        result.append(String.format("  ... and %d more\n", refsTo.size() - 10));
                        break;
                    }
                    Address fromAddr = ref.getFromAddress();
                    Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                    String funcName = fromFunc != null ? fromFunc.getName() : "<undefined>";
                    result.append(String.format("  %s from %s [%s]\n", 
                        ref.getReferenceType(), fromAddr, funcName));
                    refCount++;
                }
            }
            
            return result.toString();
            
        } catch (Exception e) {
            return "Error analyzing entry: " + e.getMessage();
        }
    }

    /**
     * Create a new memory segment/block in the program.
     * 
     * @param name      Name of the segment (e.g., "DIAG_RAM")
     * @param startStr  Start address in hex (e.g., "0xFEBDE000")
     * @param lengthStr Length in hex or decimal (e.g., "0x2000" or "8192")
     * @param type      Memory type: "RAM", "ROM", "CODE", "DATA", etc.
     * @param read      Read permission (default: true)
     * @param write     Write permission (default: true)
     * @param execute   Execute permission (default: true)
     * @param volatileMem Whether memory is volatile (default: false)
     * @param overlay   Create as overlay block (default: false)
     * @return Result message
     */
    private String createMemorySegment(String name, String startStr, String lengthStr, 
                                        String type, boolean read, boolean write, 
                                        boolean execute, boolean volatileMem, boolean overlay) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        
        if (name == null || name.isEmpty()) return "Segment name is required";
        if (startStr == null || startStr.isEmpty()) return "Start address is required";
        if (lengthStr == null || lengthStr.isEmpty()) return "Length is required";
        
        final StringBuilder result = new StringBuilder();
        
        try {
            // Parse start address
            Address startAddr = program.getAddressFactory().getAddress(startStr);
            if (startAddr == null) {
                // Try parsing as hex number and creating in default space
                long startLong = parseHexOrDecimal(startStr);
                startAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(startLong);
            }
            if (startAddr == null) {
                return "Invalid start address: " + startStr;
            }
            
            // Parse length
            long length = parseHexOrDecimal(lengthStr);
            if (length <= 0) {
                return "Invalid length: " + lengthStr;
            }
            
            final Address finalStartAddr = startAddr;
            final long finalLength = length;
            
            // Determine memory type defaults
            final boolean finalRead = read;
            final boolean finalWrite;
            final boolean finalExecute;
            
            if (type != null) {
                String typeUpper = type.toUpperCase();
                if (typeUpper.equals("RAM")) {
                    finalWrite = write;
                    finalExecute = execute;
                } else if (typeUpper.equals("ROM") || typeUpper.equals("FLASH")) {
                    finalWrite = false; // ROM is not writable by default
                    finalExecute = execute;
                } else if (typeUpper.equals("CODE")) {
                    finalWrite = write;
                    finalExecute = true;
                } else if (typeUpper.equals("DATA")) {
                    finalWrite = write;
                    finalExecute = false;
                } else {
                    finalWrite = write;
                    finalExecute = execute;
                }
            } else {
                finalWrite = write;
                finalExecute = execute;
            }
            
            SwingUtilities.invokeAndWait(() -> {
                int txId = program.startTransaction("Create memory segment: " + name);
                boolean success = false;
                try {
                    Memory memory = program.getMemory();
                    
                    // Check for overlapping blocks
                    MemoryBlock existingBlock = memory.getBlock(finalStartAddr);
                    if (existingBlock != null && !overlay) {
                        result.append(String.format("Error: Address %s is already in block '%s'\n", 
                            finalStartAddr, existingBlock.getName()));
                        result.append("Use overlay=true to create an overlay block");
                        return;
                    }
                    
                    // Use command to create initialized memory block (filled with zeros)
                    ghidra.app.cmd.memory.AddInitializedMemoryBlockCmd cmd = 
                        new ghidra.app.cmd.memory.AddInitializedMemoryBlockCmd(
                            name,
                            null, // comment
                            type != null ? type.toUpperCase() : "RAM", // source
                            finalStartAddr,
                            finalLength,
                            finalRead,
                            finalWrite,
                            finalExecute,
                            volatileMem,
                            (byte) 0x00,  // initial value - fill with zeros
                            overlay
                        );
                    
                    if (cmd.applyTo(program)) {
                        MemoryBlock newBlock = memory.getBlock(finalStartAddr);
                        if (newBlock != null) {
                            Address endAddr = finalStartAddr.add(finalLength - 1);
                            result.append(String.format("Created segment '%s'\n", name));
                            result.append(String.format("  Range: %s - %s\n", finalStartAddr, endAddr));
                            result.append(String.format("  Size: 0x%X (%d bytes)\n", finalLength, finalLength));
                            result.append(String.format("  Type: %s\n", type != null ? type.toUpperCase() : "RAM"));
                            result.append(String.format("  Permissions: %s%s%s\n", 
                                finalRead ? "R" : "-",
                                finalWrite ? "W" : "-",
                                finalExecute ? "X" : "-"));
                            result.append("  Initialized: YES (zero-filled)\n");
                            if (volatileMem) {
                                result.append("  Volatile: YES\n");
                            }
                            if (overlay) {
                                result.append("  Overlay: YES\n");
                            }
                            success = true;
                        } else {
                            result.append("Block created but could not retrieve it");
                        }
                    } else {
                        result.append("Failed to create segment: " + cmd.getStatusMsg());
                    }
                    
                } catch (Throwable e) {
                    result.append("Error creating segment: " + e.getClass().getSimpleName() + " - " + e.getMessage());
                } finally {
                    program.endTransaction(txId, success);
                }
            });
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
        
        return result.toString();
    }

    /**
     * Parse a string as hex (0x prefix) or decimal number.
     */
    private long parseHexOrDecimal(String str) {
        if (str == null || str.isEmpty()) return 0;
        str = str.trim();
        try {
            if (str.startsWith("0x") || str.startsWith("0X")) {
                return Long.parseLong(str.substring(2), 16);
            } else if (str.startsWith("-0x") || str.startsWith("-0X")) {
                return -Long.parseLong(str.substring(3), 16);
            } else {
                return Long.parseLong(str);
            }
        } catch (NumberFormatException e) {
            // Try parsing as hex without prefix
            try {
                return Long.parseLong(str, 16);
            } catch (NumberFormatException e2) {
                return 0;
            }
        }
    }


    /**
     * Create a function at the specified address.
     */
    private String createFunctionAtAddress(String addressStr, String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        
        final StringBuilder result = new StringBuilder();
        final Address addr;
        
        try {
            addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "Invalid address: " + addressStr;
        } catch (Exception e) {
            return "Invalid address format: " + addressStr;
        }
        
        // Check if function already exists
        Function existingFunc = program.getFunctionManager().getFunctionAt(addr);
        if (existingFunc != null) {
            return String.format("Function already exists at %s: %s", addr, existingFunc.getName());
        }
        
        // Check if there's an instruction at the address
        Instruction instr = program.getListing().getInstructionAt(addr);
        if (instr == null) {
            return String.format("No instruction at %s - cannot create function (this is data)", addr);
        }
        
        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = program.startTransaction("Create function at " + addr);
                try {
                    ghidra.app.cmd.function.CreateFunctionCmd cmd = 
                        new ghidra.app.cmd.function.CreateFunctionCmd(addr);
                    
                    boolean success = cmd.applyTo(program, new ConsoleTaskMonitor());
                    
                    if (success) {
                        Function newFunc = program.getFunctionManager().getFunctionAt(addr);
                        if (newFunc != null) {
                            // Set custom name if provided
                            if (name != null && !name.isEmpty()) {
                                try {
                                    newFunc.setName(name, SourceType.USER_DEFINED);
                                    result.append(String.format("Created function '%s' at %s", name, addr));
                                } catch (Exception e) {
                                    result.append(String.format("Created function at %s (naming failed: %s)", 
                                        addr, e.getMessage()));
                                }
                            } else {
                                result.append(String.format("Created function '%s' at %s", 
                                    newFunc.getName(), addr));
                            }
                            
                            // Add function size info
                            result.append(String.format(" [%d bytes]", 
                                newFunc.getBody().getNumAddresses()));
                        } else {
                            result.append("Function created but could not retrieve it");
                        }
                    } else {
                        result.append("Failed to create function: " + cmd.getStatusMsg());
                    }
                } catch (Exception e) {
                    result.append("Error creating function: " + e.getMessage());
                } finally {
                    program.endTransaction(txId, true);
                }
            });
        } catch (Exception e) {
            return "Error executing on Swing thread: " + e.getMessage();
        }
        
        return result.toString();
    }


    /**
     * Decompile a function and return the results
     */
    private DecompileResults decompileFunction(Function func, Program program) {
        // Set up decompiler for accessing the decompiled function
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile"); // Full decompilation

        // Decompile the function
        DecompileResults results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());

        if (!results.decompileCompleted()) {
            Msg.error(this, "Could not decompile function: " + results.getErrorMessage());
            return null;
        }

        return results;
    }

    /**
     * Apply the type update in a transaction
     */
    private void updateVariableType(Program program, HighSymbol symbol, DataType dataType, AtomicBoolean success) {
        int tx = program.startTransaction("Set variable type");
        try {
            // Use HighFunctionDBUtil to update the variable with the new type
            HighFunctionDBUtil.updateDBVariable(
                symbol,                // The high symbol to modify
                symbol.getName(),      // Keep original name
                dataType,              // The new data type
                SourceType.USER_DEFINED // Mark as user-defined
            );

            success.set(true);
            Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");
        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Get all references to a specific address (xref to)
     */
    private String getXrefsTo(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            ReferenceIterator refIter = refManager.getReferencesTo(addr);
            
            List<String> refs = new ArrayList<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();
                
                Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                
                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references to address: " + e.getMessage();
        }
    }

    /**
     * Get all references from a specific address (xref from)
     */
    private String getXrefsFrom(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            Reference[] references = refManager.getReferencesFrom(addr);
            
            List<String> refs = new ArrayList<>();
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                RefType refType = ref.getReferenceType();
                
                String targetInfo = "";
                Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                if (toFunc != null) {
                    targetInfo = " to function " + toFunc.getName();
                } else {
                    Data data = program.getListing().getDataAt(toAddr);
                    if (data != null) {
                        targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
                    }
                }
                
                refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references from address: " + e.getMessage();
        }
    }

    /**
     * Get all references to a specific function by name
     */
    private String getFunctionXrefs(String functionName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Function name is required";

        try {
            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = program.getFunctionManager();
            for (Function function : funcManager.getFunctions(true)) {
                if (function.getName().equals(functionName)) {
                    Address entryPoint = function.getEntryPoint();
                    ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entryPoint);
                    
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Address fromAddr = ref.getFromAddress();
                        RefType refType = ref.getReferenceType();
                        
                        Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                        String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                        
                        refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
                    }
                }
            }
            
            if (refs.isEmpty()) {
                return "No references found to function: " + functionName;
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting function references: " + e.getMessage();
        }
    }

    /**
     * List defined strings in the program with filtering options.
     * 
     * @param offset Pagination offset
     * @param limit Maximum number of strings to return
     * @param filter Substring filter (case-insensitive)
     * @param minLength Minimum string length (default: 4)
     * @param maxLength Maximum string length (0 = no limit)
     * @param segment Filter by memory segment name (e.g., ".rodata", ".data")
     * @param summary If true, return only statistics without listing strings
     * @return Formatted string list or summary statistics
     */
    private String listDefinedStrings(int offset, int limit, String filter, 
                                    int minLength, int maxLength, 
                                    String segment, boolean summary) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);
        
        // Statistics counters
        int totalStrings = 0;
        int matchedStrings = 0;
        int shortestLength = Integer.MAX_VALUE;
        int longestLength = 0;
        Map<String, Integer> segmentCounts = new HashMap<>();
        
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            
            if (data != null && isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";
                int strLength = value.length();
                totalStrings++;
                
                // Track statistics
                if (strLength < shortestLength && strLength > 0) shortestLength = strLength;
                if (strLength > longestLength) longestLength = strLength;
                
                // Track segment counts
                MemoryBlock block = program.getMemory().getBlock(data.getAddress());
                String blockName = (block != null) ? block.getName() : "unknown";
                segmentCounts.merge(blockName, 1, Integer::sum);
                
                // Apply filters
                if (strLength < minLength) continue;
                if (maxLength > 0 && strLength > maxLength) continue;
                if (filter != null && !value.toLowerCase().contains(filter.toLowerCase())) continue;
                if (segment != null && !blockName.equalsIgnoreCase(segment)) continue;
                
                matchedStrings++;
                
                if (!summary) {
                    String escapedValue = escapeString(value);
                    // Truncate very long strings for display
                    if (escapedValue.length() > 100) {
                        escapedValue = escapedValue.substring(0, 97) + "...";
                    }
                    lines.add(String.format("%s [%s] (%d): \"%s\"", 
                        data.getAddress(), blockName, strLength, escapedValue));
                }
            }
        }
        
        // Return summary if requested
        if (summary) {
            StringBuilder sb = new StringBuilder();
            sb.append("=== String Statistics ===\n\n");
            sb.append(String.format("Total defined strings: %d\n", totalStrings));
            sb.append(String.format("Matched strings (with current filters): %d\n", matchedStrings));
            sb.append(String.format("Shortest string: %d chars\n", shortestLength == Integer.MAX_VALUE ? 0 : shortestLength));
            sb.append(String.format("Longest string: %d chars\n", longestLength));
            sb.append("\nStrings by segment:\n");
            
            // Sort segments by count descending
            segmentCounts.entrySet().stream()
                .sorted((a, b) -> b.getValue().compareTo(a.getValue()))
                .forEach(e -> sb.append(String.format("  %s: %d strings\n", e.getKey(), e.getValue())));
            
            sb.append("\nCurrent filters:\n");
            sb.append(String.format("  Min length: %d\n", minLength));
            sb.append(String.format("  Max length: %s\n", maxLength > 0 ? maxLength : "unlimited"));
            if (filter != null) sb.append(String.format("  Contains: \"%s\"\n", filter));
            if (segment != null) sb.append(String.format("  Segment: %s\n", segment));
            
            return sb.toString();
        }
        
        if (lines.isEmpty()) {
            return "No strings found matching the criteria";
        }
        
        // Add header with match info
        StringBuilder result = new StringBuilder();
        result.append(String.format("Found %d strings (showing %d-%d):\n\n", 
            matchedStrings, 
            Math.min(offset + 1, matchedStrings),
            Math.min(offset + limit, matchedStrings)));
        result.append(paginateList(lines, offset, limit));
        
        return result.toString();
    }

    /**
     * Check if the given data is a string type
     */
    private boolean isStringData(Data data) {
        if (data == null) return false;
        
        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    /**
     * Escape special characters in a string for display
     */
    private String escapeString(String input) {
        if (input == null) return "";
        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else {
                sb.append(String.format("\\x%02x", (int)c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * Resolves a data type by name, handling common types and pointer types
     * @param dtm The data type manager
     * @param typeName The type name to resolve
     * @return The resolved DataType, or null if not found
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        String trimmed = typeName.trim();
        
        // Handle pointer types (e.g., "void *", "int*", "char *")
        if (trimmed.endsWith("*")) {
            String baseTypeName = trimmed.substring(0, trimmed.length() - 1).trim();
            DataType baseType = findBaseType(baseTypeName);
            if (baseType != null) {
                return dtm.getPointer(baseType);
            }
            return null;
        }
        
        // Handle array types (e.g., "int[10]", "char[256]")
        if (trimmed.contains("[") && trimmed.endsWith("]")) {
            int bracketStart = trimmed.indexOf('[');
            String baseTypeName = trimmed.substring(0, bracketStart).trim();
            String sizeStr = trimmed.substring(bracketStart + 1, trimmed.length() - 1).trim();
            
            DataType baseType = findBaseType(baseTypeName);
            if (baseType != null) {
                try {
                    int size = Integer.parseInt(sizeStr);
                    return new ArrayDataType(baseType, size, baseType.getLength());
                } catch (NumberFormatException e) {
                    Msg.error(this, "Invalid array size: "  + sizeStr, e);
                }
            }
            return null;
        }
        
        // Regular type lookup
        return findBaseType(trimmed);
    }
    
    private DataType findBaseType(String typeName) {
        DataTypeManager dtm = getCurrentProgram().getDataTypeManager();
        
        // Handle "void" specially
        if (typeName.equalsIgnoreCase("void")) {
            return DataType.VOID;
        }
        
        // Try direct path lookup
        DataType dt = dtm.getDataType("/" + typeName);
        if (dt != null) return dt;
        
        // Search in program's data type manager
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dataType = iter.next();
            if (dataType.getName().equalsIgnoreCase(typeName)) {
                return dataType;
            }
        }
        
        // Search built-in types
        BuiltInDataTypeManager builtIn = BuiltInDataTypeManager.getDataTypeManager();
        Iterator<DataType> builtInIter = builtIn.getAllDataTypes();
        while (builtInIter.hasNext()) {
            DataType dataType = builtInIter.next();
            if (dataType.getName().equalsIgnoreCase(typeName)) {
                return dataType;
            }
        }
        
        return null;
    }

    /**
     * Find a data type by name in all categories/folders of the data type manager
     * This searches through all categories rather than just the root
     */
    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        // Try exact match first
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }

        // Try lowercase
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    /**
     * Helper method to search for a data type by name in all categories
     */
    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        // Get all data types from the manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            // Check if the name matches exactly (case-sensitive) 
            if (dt.getName().equals(name)) {
                return dt;
            }
            // For case-insensitive, we want an exact match except for case
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }

    // ----------------------------------------------------------------------------------
    // Utility: parse query params, parse post params, pagination, etc.
    // ----------------------------------------------------------------------------------

    /**
     * Parse query parameters from the URL, e.g. ?offset=10&limit=100
     */
    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery(); // e.g. offset=10&limit=100
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=");
                if (kv.length == 2) {
                    // URL decode parameter values
                    try {
                        String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                        result.put(key, value);
                    } catch (Exception e) {
                        Msg.error(this, "Error decoding URL parameter", e);
                    }
                }
            }
        }
        return result;
    }

    /**
     * Parse post body form params, e.g. oldName=foo&newName=bar
     */
    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=");
            if (kv.length == 2) {
                // URL decode parameter values
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    params.put(key, value);
                } catch (Exception e) {
                    Msg.error(this, "Error decoding URL parameter", e);
                }
            }
        }
        return params;
    }

    /**
     * Create a new structure data type in the program's data type manager.
     *
     * Example request:
     *   GET /createStruct?name=notify_msg_envelope_t&fields=message_type:uint32_t:4,conn_ctx:pointer:4,payload:byte[0x4008]:16392,data_length:uint16_t:2,_pad:uint16_t:2,client_ip:uint32_t:4
     *
     * Fields format: comma-separated "name:type:size" triples.
     *   - name: field name
     *   - type: Ghidra data type string (e.g. "uint32_t", "byte[0x4008]", "pointer")
     *   - size: field size in bytes (decimal or 0x hex)
     *
     * @param name       Structure name
     * @param fieldsJson Comma-separated field descriptors
     * @return Summary of the created structure
     */
    private String createStruct(String name, String fieldsJson) {
        Program program = getCurrentProgram();
        DataTypeManager dtm = program.getDataTypeManager();

        // Check if struct already exists
        DataType existing = dtm.getDataType("/" + name);
        if (existing != null) {
            return "Error: struct '" + name + "' already exists at " + existing.getCategoryPath();
        }

        StructureDataType struct = new StructureDataType(name, 0);

        String[] fieldDefs = fieldsJson.split(",");
        StringBuilder sb = new StringBuilder();
        sb.append("Created struct '").append(name).append("':\n");

        int offset = 0;
        for (String fieldDef : fieldDefs) {
            String[] parts = fieldDef.trim().split(":");
            if (parts.length < 3) {
                return "Error: invalid field spec '" + fieldDef + "', expected name:type:size";
            }

            String fieldName = parts[0].trim();
            String typeName = parts[1].trim();
            int fieldSize = parseSize(parts[2].trim());

            DataType fieldType = resolveDataType(dtm, typeName, fieldSize);
            struct.add(fieldType, fieldSize, fieldName, null);

            sb.append(String.format("  +0x%04X  %-24s  %s (%d bytes)\n",
                    offset, fieldName, fieldType.getDisplayName(), fieldSize));
            offset += fieldSize;
        }

        sb.append(String.format("  Total size: 0x%X (%d bytes)\n", offset, offset));

        // Commit to the program's data type manager
        int txId = program.startTransaction("Create struct " + name);
        try {
            dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
        } finally {
            program.endTransaction(txId, true);
        }

        sb.append("Struct added to data type manager.");
        return sb.toString();
    }

    /**
     * Parse a size value that may be decimal or hex (0x prefix).
     */
    private int parseSize(String s) {
        if (s.startsWith("0x") || s.startsWith("0X")) {
            return Integer.parseInt(s.substring(2), 16);
        }
        return Integer.parseInt(s);
    }
    
    /**
     * Resolve a type name string into a Ghidra DataType.
     * Handles primitives, pointers, and array notation like "byte[0x4008]".
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName, int fieldSize) {
        // Try array syntax: type[count]
        if (typeName.contains("[")) {
            int bracketOpen = typeName.indexOf('[');
            int bracketClose = typeName.indexOf(']');
            String baseTypeName = typeName.substring(0, bracketOpen).trim();
            String countStr = typeName.substring(bracketOpen + 1, bracketClose).trim();
            int count = parseSize(countStr);

            DataType baseType = resolvePrimitive(dtm, baseTypeName);
            return new ArrayDataType(baseType, count, baseType.getLength());
        }

        // Pointer type
        if (typeName.equals("pointer") || typeName.equals("void*") || typeName.equals("ptr")) {
            return PointerDataType.dataType;
        }

        return resolvePrimitive(dtm, typeName);
    }

    private DataType resolvePrimitive(DataTypeManager dtm, String typeName) {
        // Try the program's DTM first (catches typedefs, user-defined types)
        DataType dt = dtm.getDataType("/" + typeName);
        if (dt != null) return dt;

        // Built-in primitives
        switch (typeName.toLowerCase()) {
            case "byte":
            case "uint8_t":
            case "uchar":
                return ByteDataType.dataType;
            case "char":
            case "int8_t":
                return CharDataType.dataType;
            case "short":
            case "int16_t":
                return ShortDataType.dataType;
            case "ushort":
            case "uint16_t":
            case "word":
                return UnsignedShortDataType.dataType;
            case "int":
            case "int32_t":
                return IntegerDataType.dataType;
            case "uint":
            case "uint32_t":
            case "dword":
                return UnsignedIntegerDataType.dataType;
            case "long":
            case "int64_t":
                return LongDataType.dataType;
            case "ulong":
            case "uint64_t":
            case "qword":
                return UnsignedLongDataType.dataType;
            case "float":
                return FloatDataType.dataType;
            case "double":
                return DoubleDataType.dataType;
            case "bool":
            case "boolean":
                return BooleanDataType.dataType;
            case "void":
                return VoidDataType.dataType;
            default:
                // Try built-in DTM as last resort
                DataType builtIn = BuiltInDataTypeManager.getDataTypeManager()
                        .getDataType("/" + typeName);
                if (builtIn != null) return builtIn;
                return Undefined.getUndefinedDataType(1);
        }
    }

    /**
     * Convert a list of strings into one big newline-delimited string, applying offset & limit.
     */
    private String paginateList(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end   = Math.min(items.size(), offset + limit);

        if (start >= items.size()) {
            return ""; // no items in range
        }
        List<String> sub = items.subList(start, end);
        return String.join("\n", sub);
    }

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Escape non-ASCII chars to avoid potential decode issues.
     */
    private String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            }
            else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    @Override
    public void dispose() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server...");
            server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
            server = null; // Nullify the reference
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
        super.dispose();
    }
}
