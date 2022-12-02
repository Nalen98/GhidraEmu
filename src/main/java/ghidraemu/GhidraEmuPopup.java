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
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

public class GhidraEmuPopup extends ListingContextAction {
    public final String MenuName = "GhidraEmu";
    public final String Group_Name = "GhidraEmu";
    public static PluginTool tool;
    public static Program program;
    public static Address start_address = null;
    public static Address stop_address = null;
    public static ArrayList < PatchedBytes > bytesToPatch = new ArrayList < PatchedBytes > ();

    public GhidraEmuPopup(GhidraEmuPlugin plugin, Program program) {
        super("GhidraEmuPlugin", plugin.getName());
        setProgram(program);
        tool = plugin.getTool();
        setupActions();
    }

    public void setProgram(Program p) {
        program = p;
    }

    public void setupActions() {
        tool.setMenuGroup(new String[] {
            MenuName
        }, Group_Name);

        ListingContextAction EmuStart = new ListingContextAction("Start emulation here", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                if (context.getLocation().getAddress() != start_address) {
                    if (start_address != null) {
                        UnSetColor(start_address);
                    }
                    start_address = context.getLocation().getAddress();
                    SetColor(start_address, Color.GREEN);
                    RegisterProvider.setRegister(RegisterProvider.PC, start_address);
                    GhidraEmuProvider.StartTF.setText("0x" + context.getLocation().getAddress().toString());
                }
            }
        };
        EmuStart.setKeyBindingData(new KeyBindingData(KeyEvent.VK_Z, 0));
        EmuStart.setPopupMenuData(new MenuData(new String[] {
            MenuName,
            "Start emulation here"
        }, null, Group_Name));
        tool.addAction(EmuStart);

        ListingContextAction EmuStop = new ListingContextAction("Stop emulation here", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                if (context.getLocation().getAddress() != stop_address) {
                    if (stop_address != null) {
                        UnSetColor(stop_address);
                    }
                    stop_address = context.getLocation().getAddress();
                    SetColor(stop_address, Color.CYAN);
                    GhidraEmuProvider.StopTF.setText("0x" + context.getLocation().getAddress().toString());
                }
            }
        };
        EmuStop.setKeyBindingData(new KeyBindingData(KeyEvent.VK_X, 0));
        EmuStop.setPopupMenuData(new MenuData(new String[] {
            MenuName,
            "Stop emulation here"
        }, null, Group_Name));
        tool.addAction(EmuStop);

        ListingContextAction ApplyPatchedBytes = new ListingContextAction("Apply Patched Bytes", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                Address StartAddress = context.getSelection().getMinAddress();
                List < Byte > patched = new ArrayList < Byte > ();
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
                bytesToPatch.add(new PatchedBytes(StartAddress, pbytes));
            }
        };

        ApplyPatchedBytes.setPopupMenuData(new MenuData(new String[] {
            MenuName,
            "Apply Patched Bytes"
        }, null, Group_Name));
        tool.addAction(ApplyPatchedBytes);

        ListingContextAction SetBreak = new ListingContextAction("Add breakpoint", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                Address address = context.getLocation().getAddress();
                SetColor(address, Color.RED);
                if (!GhidraEmuProvider.breaks.contains(address)) {
                    GhidraEmuProvider.breaks.add(address);
                    BreakpointProvider.Breakmodel.addRow(new Object[] {
                        BreakpointProvider.BIcon, BigInteger.valueOf(address.getOffset())
                    });
                }
            }
        };
        SetBreak.setKeyBindingData(new KeyBindingData(KeyEvent.VK_K, 0));
        SetBreak.setPopupMenuData(new MenuData(new String[] {
            MenuName,
            "Add breakpoint"
        }, null, Group_Name));
        tool.addAction(SetBreak);
        ListingContextAction UnSetBreak = new ListingContextAction("Delete breakpoint", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                Address address = context.getLocation().getAddress();
                UnSetColor(address);
                GhidraEmuProvider.breaks.remove(address);
                for (int i = 0; i < BreakpointProvider.Breakmodel.getRowCount(); i++) {
                    if (BreakpointProvider.Breakmodel.getValueAt(i, 1).equals(BigInteger.valueOf(address.getOffset()))) {
                        BreakpointProvider.Breakmodel.removeRow(i);
                    }
                }
            }
        };
        UnSetBreak.setKeyBindingData(new KeyBindingData(KeyEvent.VK_J, 0));
        UnSetBreak.setPopupMenuData(new MenuData(new String[] {
            MenuName,
            "Delete breakpoint"
        }, null, Group_Name));
        tool.addAction(UnSetBreak);
    }

    public static void UnSetColor(Address address) {
        ColorizingService service = tool.getService(ColorizingService.class);
        int TransactionID = program.startTransaction("UnSetColor");
        service.clearBackgroundColor(address, address);
        program.endTransaction(TransactionID, true);
    }

    public static void SetColor(Address address, Color color) {
        ColorizingService service = tool.getService(ColorizingService.class);
        int TransactionID = program.startTransaction("SetColor");
        service.setBackgroundColor(address, address, color);
        program.endTransaction(TransactionID, true);
    }

    public static class PatchedBytes {
        public Address start;
        public byte[] bytes;

        PatchedBytes(Address start, byte[] bytes) {
            this.start = start;
            this.bytes = bytes;
        }
    }
}
