package ghidraemu;

import byteviewerEmu.ByteViewerPluginEmu;
import byteviewerEmu.ProgramByteViewerComponentProviderEmu;
import ghidra.MiscellaneousPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

//@formatter:off
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = MiscellaneousPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Ghidra Emulator",
    description = "Native pcode emulator",
    servicesRequired = { CodeViewerService.class, ConsoleService.class }
)
//@formatter:on
public class GhidraEmuPlugin extends ProgramPlugin {
    public GhidraEmuProvider provider;
    public static RegisterProvider regprovider;
    public static ProgramByteViewerComponentProviderEmu stackProvider;
    public static BreakpointProvider bpprovider;
    public ByteViewerPluginEmu stackBytesPlugin;
    public Program program;
    public static GhidraEmuPopup popup;
    public CodeViewerService codeViewer;
    public ConsoleService console;

    public GhidraEmuPlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    public void init() {
        codeViewer = tool.getService(CodeViewerService.class);
        console = tool.getService(ConsoleService.class);
        String pluginName = getName();
        provider = new GhidraEmuProvider(this, pluginName);
        regprovider = new RegisterProvider(this, pluginName);
        bpprovider = new BreakpointProvider(this, pluginName);
        stackBytesPlugin = new ByteViewerPluginEmu(tool);
        stackProvider = stackBytesPlugin.getProvider();
        stackProvider.setTitle("GhidraEmu Stack");
        stackProvider.contextChanged();
        createActions();
    }

    @Override
    protected void programActivated(Program p) {
        if (p != null) {
            if (program == null) {
                program = p;
                regprovider.setProgram(p);
                provider.setProgram(p);
                popup.setProgram(p);
                bpprovider.setProgram(p);
            }
        }
    }

    private void createActions() {
        popup = new GhidraEmuPopup(this, program);
    }

    @Override
    protected void programDeactivated(Program program) {
        // Clear the whole emulation progress to avoid errors the next time
        provider.resetState();
    }

    @Override
    protected void dispose() {
        super.dispose();
        if (!stackBytesPlugin.isDisposed()) {
            stackBytesPlugin.dispose();
        }
    }
}
