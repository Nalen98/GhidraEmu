package ghidraemu;

import java.awt.Color;
import java.awt.event.KeyEvent;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.context.NavigatableContextAction;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

public class GhidraEmuPopup extends ListingContextAction {
	public GhidraEmuPlugin ghidraEmuPlugin;
    public final String menuName = "GhidraEmu";
    public final String groupName = "GhidraEmu";
    public static PluginTool tool;    
    public static Program program;
    public static Address start_address = null;
    public static Address stop_address = null;
    public static ArrayList <PatchedBytes> bytesToPatch = new ArrayList <PatchedBytes> ();

    public GhidraEmuPopup(GhidraEmuPlugin plugin, Program program) {
        super("GhidraEmuPlugin", plugin.getName());
        setProgram(program);
        tool = plugin.getTool();
        setupActions();
        ghidraEmuPlugin = plugin;
    }

    public void setProgram(Program p) {
        program = p;
    }

    public static class PatchedBytes {
        public Address start;
        public byte[] bytes;

        PatchedBytes(Address start, byte[] bytes) {
            this.start = start;
            this.bytes = bytes;
        }
    }

    public void setupActions() {
        tool.setMenuGroup(new String[] {
            menuName
        }, groupName);

        ListingContextAction emuStart = new ListingContextAction("Start emulation here", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                if (context.getLocation().getAddress() != start_address) {
                    if (start_address != null) {
                        unsetColor(start_address);
                    }
                    start_address = context.getLocation().getAddress();                   
                    setColor(start_address, Color.GREEN);                    
                    Long addressableWordOffset = start_address.getAddressableWordOffset();
                   
                    RegisterProvider.setRegister(RegisterProvider.PC, BigInteger.valueOf(addressableWordOffset));
                    GhidraEmuProvider.startTF.setText("0x" + Long.toHexString(addressableWordOffset));
                }
            }
        };
        emuStart.setKeyBindingData(new KeyBindingData(KeyEvent.VK_Z, 0));
        emuStart.setPopupMenuData(new MenuData(new String[] {
            menuName,
            "Start emulation here"
        }, null, groupName));
        tool.addAction(emuStart);

        ListingContextAction emuStop = new ListingContextAction("Stop emulation here", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                if (context.getLocation().getAddress() != stop_address) {
                    if (stop_address != null) {
                        unsetColor(stop_address);
                    }
                    stop_address = context.getLocation().getAddress();
                    setColor(stop_address, Color.CYAN);
                    GhidraEmuProvider.stopTF.setText("0x" + Long.toHexString(stop_address.getAddressableWordOffset()));
                }
            }
        };
        emuStop.setKeyBindingData(new KeyBindingData(KeyEvent.VK_X, 0));
        emuStop.setPopupMenuData(new MenuData(new String[] {
            menuName,
            "Stop emulation here"
        }, null, groupName));
        tool.addAction(emuStop);

        ListingContextAction applyPatchedBytes = new ListingContextAction("Apply Patched Bytes", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                Address startAddress = context.getSelection().getMinAddress();
                List <Byte> patched = new ArrayList <Byte> ();
                for (Address address: context.getSelection().getAddresses(true)) {
                    byte Byte = 0;
                    try {
                        Byte = context.getProgram().getMemory().getByte(address);
                    } catch (MemoryAccessException e) {                        
                        e.printStackTrace();
                    }
                    patched.add(Byte);
                }
                byte[] pbytes = new byte[patched.size()];
                int counter = 0;
                for (Byte b: patched) {
                    pbytes[counter] = b;
                    counter++;
                }
                bytesToPatch.add(new PatchedBytes(startAddress, pbytes));
            }
        };
        applyPatchedBytes.setKeyBindingData(new KeyBindingData(KeyEvent.VK_M, 0));
        applyPatchedBytes.setPopupMenuData(new MenuData(new String[] {
            menuName,
            "Apply Patched Bytes"
        }, null, groupName));
        tool.addAction(applyPatchedBytes);

        ListingContextAction setBreak = new ListingContextAction("Add breakpoint", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                Address address = context.getLocation().getAddress();
                setColor(address, Color.RED);                
                if (!GhidraEmuProvider.breaks.contains(address)) {
                    GhidraEmuProvider.breaks.add(address);
                    BreakpointProvider.breakModel.addRow(new Object[] {
                        BreakpointProvider.breakpointIcon, BigInteger.valueOf(address.getAddressableWordOffset())
                    });
                }
            }
        };
        setBreak.setKeyBindingData(new KeyBindingData(KeyEvent.VK_K, 0));
        setBreak.setPopupMenuData(new MenuData(new String[] {
            menuName,
            "Add breakpoint"
        }, null, groupName));
        tool.addAction(setBreak);
        ListingContextAction unsetBreak = new ListingContextAction("Delete breakpoint", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                Address address = context.getLocation().getAddress();
                unsetColor(address);
                GhidraEmuProvider.breaks.remove(address);
                for (int i = 0; i <BreakpointProvider.breakModel.getRowCount(); i++) {
                    if (BreakpointProvider.breakModel.getValueAt(i, 1).equals(BigInteger.valueOf(address.getAddressableWordOffset()))) {
                        BreakpointProvider.breakModel.removeRow(i);
                    }
                }
                if (GhidraEmuProvider.emuHelper != null){
                    GhidraEmuProvider.emuHelper.clearBreakpoint(address);
                }
            }
        };
        unsetBreak.setKeyBindingData(new KeyBindingData(KeyEvent.VK_T, 0));
        unsetBreak.setPopupMenuData(new MenuData(new String[] {
            menuName,
            "Delete breakpoint"
        }, null, groupName));
        tool.addAction(unsetBreak);
        
        // new feature - jump over the instruction
        NavigatableContextAction jumpOver = new NavigatableContextAction("Jump over the instruction", getName()) {
            @Override
            protected void actionPerformed(NavigatableActionContext context) {
                if (GhidraEmuProvider.emuHelper != null && ghidraEmuPlugin != null) {
                	ghidraEmuPlugin.provider.jumpOver();
                }
            }
        };
        jumpOver.setKeyBindingData(new KeyBindingData(KeyEvent.VK_J, 0));
        jumpOver.setPopupMenuData(new MenuData(new String[] {
            menuName,
            "Jump over"
        }, null, groupName));
        tool.addAction(jumpOver);

        // new feature - step over the subroutine
        NavigatableContextAction stepOver = new NavigatableContextAction("Step over the subroutine", getName()) {
            @Override
            protected void actionPerformed(NavigatableActionContext context) {   
                if (GhidraEmuProvider.emuHelper != null && ghidraEmuPlugin != null) {             
                	ghidraEmuPlugin.provider.stepOver();
                }
            }
        };
        stepOver.setKeyBindingData(new KeyBindingData(KeyEvent.VK_F6, 0));
        stepOver.setPopupMenuData(new MenuData(new String[] {
            menuName,
            "Step over"
        }, null, groupName));
        tool.addAction(stepOver);
    }

    public static void unsetColor(Address address) {
        int transactionID = -1;
        try {
            ColorizingService service = tool.getService(ColorizingService.class);
            transactionID = program.startTransaction("UnSetColor");
            service.clearBackgroundColor(address, address);
        } catch (Exception ex) { 
            ex.printStackTrace(); 
        } finally {       
            program.endTransaction(transactionID, true);
        } 
    }

    public static void setColor(Address address, Color color) {
        int transactionID = -1;
        try {
            ColorizingService service = tool.getService(ColorizingService.class);
            transactionID = program.startTransaction("SetColor");
            service.setBackgroundColor(address, address, color);            
        } catch (Exception ex) { 
            ex.printStackTrace(); 
        } finally {       
            program.endTransaction(transactionID, true);
        } 
    }
}
