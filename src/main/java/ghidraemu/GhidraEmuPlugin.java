package ghidraemu;

import byteviewerEmu.ByteViewerPluginEmu;
import byteviewerEmu.ProgramByteViewerComponentProviderEmu;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ConsoleService;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;


//@formatter:off
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = ExamplesPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Ghidra Emulator",
    description = "Native pcode emulator",
    servicesRequired = { CodeViewerService.class, ConsoleService.class }
)
//@formatter:on
public class GhidraEmuPlugin extends ProgramPlugin {    
    public GhidraEmuProvider provider;
    public static RegisterProvider regprovider;
    public static ProgramByteViewerComponentProviderEmu stackprovider;	
    public static BreakpointProvider bpprovider;
    public ByteViewerPluginEmu bytePlugin;
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
        bytePlugin = new ByteViewerPluginEmu(tool);
        stackprovider = bytePlugin.getProvider();	
        stackprovider.setTitle("GhidraEmu Stack");
        stackprovider.contextChanged(); 
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
                long stackOffset =
                    (program.getMinAddress().getAddressSpace().getMaxAddress().getOffset() >>> 5) - 0x7fff;
                ProgramLocation location = new ProgramLocation(program, program.getAddressFactory().getAddress(Long.toHexString(stackOffset)));    
                stackprovider.goTo(program, location);
            }
        }
    }
    
    private void createActions() {    	
        popup = new GhidraEmuPopup(this, program);
    }
    
    @Override
    protected void dispose() {		
        super.dispose();
        if (!bytePlugin.isDisposed()) {	
            bytePlugin.dispose();
        }			
    }
}
