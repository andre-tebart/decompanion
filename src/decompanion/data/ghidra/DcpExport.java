// Decompile every function of the current program and write one JSON file in the shape `dcp ghidra import`
// reads (the REA batch_decompile result): subject.digest.sha256, normalized_result.items[] with address,
// status, procedure {address, name}, pseudocode, plus the function's body (start, end, size, ranges).
// Usage (analyzeHeadless post-script): -postScript DcpExport.java <out.json> [<timeout seconds> [<starts file>]]
// The starts file lists one hex address per line: function starts the ledger knows; where Ghidra has no function
// the script creates one before decompiling (so every start of ours gets a draft), and reports how many it made.
// Shipped with decompanion (src/decompanion/data/ghidra/); run by `dcp ghidra export`.
//@category decompanion

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class DcpExport extends GhidraScript {

    private static final String SEEDED = "DCP_SEEDED";

    private static String q(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20 || c > 0x7e) {
                        b.append(String.format("\\u%04x", (int) c));
                    }
                    else {
                        b.append(c);
                    }
            }
        }
        return b.append('"').toString();
    }

    private static String hex(long v) {
        return String.format("\"0x%08x\"", v);
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException("DcpExport.java <out.json> [timeout seconds]");
        }
        int timeout = args.length > 1 ? Integer.parseInt(args[1]) : 60;
        int created = 0, refused = 0;
        if (args.length > 2) {
            for (String line : java.nio.file.Files.readAllLines(java.nio.file.Paths.get(args[2]), StandardCharsets.UTF_8)) {
                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }
                ghidra.program.model.address.Address a = toAddr(Long.parseLong(line.replace("0x", ""), 16));
                if (getFunctionAt(a) != null) {
                    continue;
                }
                if (getInstructionAt(a) == null) {
                    disassemble(a);
                }
                Function made = createFunction(a, null);
                if (made != null) {
                    created++;
                    made.addTag(SEEDED);      // kept in the project: a later export still knows it was ours
                }
                else {
                    refused++;
                }
            }
        }
        DecompInterface ifc = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        ifc.setOptions(opts);
        ifc.toggleCCode(true);
        ifc.toggleSyntaxTree(false);
        if (!ifc.openProgram(currentProgram)) {
            throw new IllegalStateException("decompiler: " + ifc.getLastMessage());
        }
        int n = 0, failed = 0;
        try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(args[0]), StandardCharsets.UTF_8))) {
            w.write("{\"tool\": " + q("ghidra " + Application.getApplicationVersion()));
            w.write(", \"created\": " + created + ", \"refused\": " + refused);
            w.write(", \"subject\": {\"digest\": {\"sha256\": " + q(currentProgram.getExecutableSHA256()) + "}}");
            w.write(", \"normalized_result\": {\"items\": [\n");
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            boolean first = true;
            while (it.hasNext() && !monitor.isCancelled()) {
                Function f = it.next();
                if (f.isExternal() || f.isThunk() && f.getBody().getNumAddresses() == 0) {
                    continue;
                }
                long entry = f.getEntryPoint().getOffset();
                StringBuilder body = new StringBuilder("[");
                long lo = Long.MAX_VALUE, hi = 0;
                boolean fr = true;
                for (AddressRange r : f.getBody()) {
                    long a = r.getMinAddress().getOffset(), b = r.getMaxAddress().getOffset() + 1;
                    lo = Math.min(lo, a);
                    hi = Math.max(hi, b);
                    body.append(fr ? "" : ", ").append("[").append(hex(a)).append(", ").append(hex(b)).append("]");
                    fr = false;
                }
                body.append("]");
                String status = "ok", text = null, err = "";
                DecompileResults res = ifc.decompileFunction(f, timeout, monitor);
                if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                    text = res.getDecompiledFunction().getC();
                }
                else {
                    status = "error";
                    err = res == null ? "no result" : String.valueOf(res.getErrorMessage());
                    failed++;
                }
                w.write(first ? "" : ",\n");
                first = false;
                w.write("{\"address\": " + hex(entry) + ", \"status\": " + q(status));
                boolean ours = false;
                for (ghidra.program.model.listing.FunctionTag tag : f.getTags()) {
                    ours = ours || SEEDED.equals(tag.getName());
                }
                if (ours) {
                    w.write(", \"seeded\": true");
                }
                w.write(", \"procedure\": {\"address\": " + hex(entry) + ", \"name\": " + q(f.getName()) + "}");
                w.write(", \"body\": {\"start\": " + hex(lo == Long.MAX_VALUE ? entry : lo) + ", \"end\": " + hex(hi == 0 ? entry + 1 : hi)
                        + ", \"size\": " + f.getBody().getNumAddresses() + ", \"ranges\": " + body + "}");
                if (text != null) {
                    w.write(", \"pseudocode\": " + q(text));
                }
                else {
                    w.write(", \"error\": " + q(err.trim()));
                }
                w.write("}");
                n++;
            }
            w.write("\n]}}\n");
        }
        finally {
            ifc.dispose();
        }
        println("DcpExport: " + n + " functions (" + created + " created at our starts, " + refused + " refused), " + failed + " failed, " + args[0]);
    }
}
