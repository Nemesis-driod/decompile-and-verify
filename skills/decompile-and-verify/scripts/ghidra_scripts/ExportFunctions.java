// ExportFunctions.java - Ghidra headless post-script. Plain Java, so it runs on any Ghidra with a JDK
// and needs no Python bridge (Jython vs PyGhidra differs between Ghidra versions).
// Args: <outdir> [maxFunctions (0 = all)] [decompile 1|0] [timeoutSecondsPerFunction]
// Writes: <outdir>/functions.csv, <outdir>/summary.txt, <outdir>/decompiled/<addr>_<name>.c
//@category Decompile

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.SourceType;
import java.io.File;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ExportFunctions extends GhidraScript {

    // Names Ghidra invents when it has nothing better: local_28, iVar1, puVar3, param_2
    private static final Pattern AUTO_VAR = Pattern.compile("\\b(local_[0-9a-fA-F]+|[a-z]{1,3}Var[0-9]+|param_[0-9]+)\\b");
    private static final Pattern GOTO = Pattern.compile("\\bgoto\\b");

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("ExportFunctions: missing <outdir> argument");
            return;
        }
        File outDir = new File(args[0]);
        int maxFunctions = args.length > 1 ? Integer.parseInt(args[1]) : 0;
        boolean wantDecompile = args.length < 3 || !args[2].equals("0");
        int timeoutSec = args.length > 3 ? Integer.parseInt(args[3]) : 30;

        File decompiledDir = new File(outDir, "decompiled");
        if (!decompiledDir.exists() && !decompiledDir.mkdirs()) {
            printerr("ExportFunctions: cannot create " + decompiledDir);
            return;
        }

        DecompInterface decomp = null;
        if (wantDecompile) {
            decomp = new DecompInterface();
            if (!decomp.openProgram(currentProgram)) {
                printerr("ExportFunctions: decompiler could not open the program: " + decomp.getLastMessage());
                decomp = null; // still export the inventory
            }
        }

        int total = 0, named = 0, okCount = 0, failCount = 0;
        try (PrintWriter csv = new PrintWriter(new File(outDir, "functions.csv"), "UTF-8")) {
            csv.println("address,name,named,size_bytes,instructions,branches,calls,jumps,is_thunk,"
                    + "decompile_status,c_lines,gotos,autovars,c_file");
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Function f = it.next();
                if (maxFunctions > 0 && total >= maxFunctions) break;
                total++;

                boolean isNamed = f.getSymbol().getSource() != SourceType.DEFAULT;
                if (isNamed) named++;

                int instructions = 0, branches = 0, calls = 0, jumps = 0;
                InstructionIterator ii = currentProgram.getListing().getInstructions(f.getBody(), true);
                while (ii.hasNext()) {
                    Instruction ins = ii.next();
                    instructions++;
                    if (ins.getFlowType().isCall()) {
                        calls++;
                    } else if (ins.getFlowType().isJump()) {
                        if (ins.getFlowType().isConditional()) branches++; else jumps++;
                    }
                }

                String status = "skipped";
                String cFile = "";
                int cLines = 0, gotos = 0, autoVars = 0;
                if (decomp != null) {
                    DecompileResults res = decomp.decompileFunction(f, timeoutSec, monitor);
                    if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                        String c = res.getDecompiledFunction().getC();
                        status = "ok";
                        okCount++;
                        cLines = c.split("\r?\n", -1).length;
                        gotos = count(GOTO, c);
                        autoVars = count(AUTO_VAR, c);
                        String safe = f.getName().replaceAll("[^A-Za-z0-9_.-]", "_");
                        cFile = "decompiled/" + f.getEntryPoint().toString() + "_" + safe + ".c";
                        Files.writeString(new File(outDir, cFile).toPath(), c);
                    } else {
                        status = (res != null && res.isTimedOut()) ? "timeout" : "failed";
                        failCount++;
                    }
                }

                csv.println(f.getEntryPoint() + ",\"" + f.getName().replace("\"", "\"\"") + "\","
                        + isNamed + "," + f.getBody().getNumAddresses() + "," + instructions + ","
                        + branches + "," + calls + "," + jumps + "," + f.isThunk() + ","
                        + status + "," + cLines + "," + gotos + "," + autoVars + "," + cFile);
            }
        }

        try (PrintWriter sum = new PrintWriter(new File(outDir, "summary.txt"), "UTF-8")) {
            sum.println("program=" + currentProgram.getName());
            sum.println("format=" + currentProgram.getExecutableFormat());
            sum.println("language=" + currentProgram.getLanguageID());
            sum.println("compiler=" + currentProgram.getCompilerSpec().getCompilerSpecID());
            sum.println("image_base=" + currentProgram.getImageBase());
            sum.println("functions=" + total);
            sum.println("named_functions=" + named);
            sum.println("decompiled_ok=" + okCount);
            sum.println("decompile_failed=" + failCount);
        }
        println("ExportFunctions: " + total + " functions, " + named + " named, " + okCount + " decompiled, "
                + failCount + " failed -> " + outDir);
    }

    private static int count(Pattern p, String s) {
        Matcher m = p.matcher(s);
        int n = 0;
        while (m.find()) n++;
        return n;
    }
}
