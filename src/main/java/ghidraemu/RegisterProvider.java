package ghidraemu;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.awt.event.ActionEvent;
import javax.swing.*;
import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.table.GTableCellRenderingData;
import docking.widgets.table.HexBigIntegerTableCellEditor;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.docking.settings.Settings;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.column.AbstractGColumnRenderer;
import resources.Icons;
import resources.ResourceManager;
import javax.swing.table.DefaultTableModel;

public class RegisterProvider extends ComponentProvider {
    private JPanel panel;
    private static final Object[][] regData = {};
    private static final Object[] columnNames = {
        "Register",
        "Value"
    };
    public Program program;
    public static GhidraTable regtable;
    public List < Register > ProgramRegisters;
    public static List < String > RegList;
    public static List < RegVal > RegsVals;
    public static String PC;
    public static String SP;
    private boolean actionsCreated;
    private DockingAction SetReturnReg;
    public BigInteger newVal;
    public static DefaultTableModel regmodel;
    public Color registerChangesColor = DebuggerResources.DEFAULT_COLOR_REGISTER_CHANGED;
    public static ArrayList < Register > ConventionRegs;
    public static String returnReg;

    public RegisterProvider(GhidraEmuPlugin ghidraEmuPlugin, String pluginName) {
        super(ghidraEmuPlugin.getTool(), "Register View", pluginName);
        setProgram(program);
        setIcon(ResourceManager.loadImage("images/ico.png"));
        setWindowMenuGroup("GhidraEmu");
        actionsCreated = false;
        returnReg = null;
    }

    /**
    * @wbp.parser.entryPoint
    */
    private void buildPanel() {
        panel = new JPanel(new BorderLayout());
        regmodel = new DefaultTableModel(regData, columnNames) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 1;
            }
        };
        RegList = new ArrayList < > ();
        ProgramRegisters = program.getProgramContext().getRegisters();

        for (Register reg: ProgramRegisters) {
            if (!reg.isHidden() && reg.isBaseRegister()) {
                if (reg.isProgramCounter()) {
                    PC = reg.getName();
                    RegList.add(0, reg.getName());
                    continue;
                }
                RegList.add(reg.getName());
            }
        }
        RegsVals = new ArrayList < RegVal > ();
        for (String reg_name: RegList) {
            RegsVals.add(new RegVal(BigInteger.valueOf(0), false));
            regmodel.addRow(new Object[] {
                reg_name,
                BigInteger.valueOf(0)
            });
        }
        ConventionRegs = new ArrayList < Register > ();
        var VarStorage = program.getCompilerSpec().getDefaultCallingConvention().getPotentialInputRegisterStorage(program);
        for (var StorageReg: VarStorage) {
            Register reg = StorageReg.getRegister();
            if (reg.isBaseRegister() && !reg.getName().contains("_")) {
                ConventionRegs.add(reg);
            }
        }
        regtable = new GhidraTable(regmodel);
        Action action = new AbstractAction() {
            public void actionPerformed(ActionEvent e) {
                TableCellListener tcl = (TableCellListener) e.getSource();
                newVal = (BigInteger) tcl.getNewValue();
                int rowVal = tcl.getRow();
                RegsVals.set(rowVal, new RegVal(newVal, true));
            }
        };
        regtable.getColumnModel().getColumn(1).setMinWidth(100);
        regtable.getColumnModel().getColumn(1).setMaxWidth(150);
        regtable.getColumnModel().getColumn(1).setCellEditor(new HexBigIntegerTableCellEditor());
        regtable.getColumnModel().getColumn(1).setCellRenderer(new HexBigIntegerTableCellRenderer());
        TableCellListener tcl = new TableCellListener(regtable, action);
        panel.add(new JScrollPane(regtable), BorderLayout.CENTER);
        setVisible(true);
    }

    public void setProgram(Program p) {
        if (p != null) {
            program = p;
            buildPanel();
            createActions();
        }
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }

    public class HexBigIntegerTableCellRenderer extends AbstractGColumnRenderer < BigInteger > {
        protected String formatBigInteger(BigInteger value) {
            return value == null ? "??" : value.toString(16);
        }

        @Override
        public Component getTableCellRendererComponent(GTableCellRenderingData data) {
            super.getTableCellRendererComponent(data);
            setText(formatBigInteger((BigInteger) data.getValue()));
            if (RegsVals.get(data.getRowViewIndex()).isEdited == true) {
                setForeground(registerChangesColor);
                regtable.repaint();
            }
            return this;
        }

        @Override
        public String getFilterString(BigInteger t, Settings settings) {
            return formatBigInteger(t);
        }
    }

    public static void setRegister(String register, Address address) {
        int counter = 0;
        for (String reg: RegList) {
            if (reg.equals(register)) {
                if (!BigInteger.valueOf(address.getOffset()).equals(RegsVals.get(counter).value)) {
                    RegsVals.set(counter, new RegVal(BigInteger.valueOf(address.getOffset()), true));
                    regtable.setValueAt(BigInteger.valueOf(address.getOffset()), counter, 1);
                    break;
                }
                RegsVals.set(counter, new RegVal(BigInteger.valueOf(address.getOffset()), false));
            }
            counter++;
        }
    }

    public static void setRegister(String register, BigInteger value) {
        int counter = 0;
        for (String reg: RegList) {
            if (reg.equals(register)) {
                if (!value.equals(RegsVals.get(counter).value)) {
                    RegsVals.set(counter, new RegVal(value, true));
                    regtable.setValueAt(value, counter, 1);
                    break;
                }
                RegsVals.set(counter, new RegVal(value, false));
            }
            counter++;
        }
    }

    public static void setRegister(String register, BigInteger value, boolean isEdited) {
        int counter = 0;
        for (String reg: RegList) {
            if (reg.equals(register)) {
                RegsVals.set(counter, new RegVal(value, isEdited));
                regtable.setValueAt(value, counter, 1);
                break;
            }
            counter++;
        }
    }

    public static class RegVal {
        public BigInteger value;
        public boolean isEdited;

        RegVal(BigInteger value, boolean isEdited) {
            this.value = value;
            this.isEdited = isEdited;
        }
    }

    private void createActions() {
        if (!actionsCreated) {
            SetReturnReg = new DockingAction("Set as link register", getName()) {
                @Override
                public void actionPerformed(ActionContext context) {
                    try {
                        int selected = regtable.getSelectedRow();
                        returnReg = RegList.get(selected);
                        JOptionPane.showMessageDialog(null, "Link register (" + returnReg + ") is set!");
                    } catch (Exception ex) {}
                }
            };
            SetReturnReg.setToolBarData(new ToolBarData(Icons.ARROW_DOWN_RIGHT_ICON, null));
            SetReturnReg.setEnabled(true);
            SetReturnReg.markHelpUnnecessary();
            dockingTool.addLocalAction(this, SetReturnReg);
            actionsCreated = true;
        }
    }
}
