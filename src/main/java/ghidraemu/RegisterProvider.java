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
    public List <Register> programRegisters;
    public static List <String> regList;
    public static List <RegVal> regsVals;
    public static String PC;
    public static String SP;
    private boolean actionsCreated;
    private DockingAction setReturnReg;
    public BigInteger newVal;
    public static DefaultTableModel regmodel;
    public Color registerChangesColor;
    public static ArrayList <Register> conventionRegs;
    public static String returnReg;

    public RegisterProvider(GhidraEmuPlugin ghidraEmuPlugin, String pluginName) {
        super(ghidraEmuPlugin.getTool(), "Registers View", pluginName);
        setProgram(program);
        setIcon(ResourceManager.loadImage("images/ico.png"));
        setWindowMenuGroup("GhidraEmu");
        actionsCreated = false;
        returnReg = null;
        registerChangesColor = DebuggerResources.DEFAULT_COLOR_REGISTER_CHANGED;
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
        regList = new ArrayList <> ();
        programRegisters = program.getProgramContext().getRegisters();  
        String processorName = program.getLanguage().getProcessor().toString();
        Boolean isV850 = processorName.equalsIgnoreCase("v850");
        Boolean isSparc = processorName.equalsIgnoreCase("sparc");
        for (Register reg: programRegisters) {
            if (!reg.isHidden()) {
                if (isV850 || isSparc || reg.isBaseRegister()) {            	
                    if (reg.isProgramCounter()) {
                        PC = reg.getName();
                        regList.add(0, reg.getName());
                        continue;
                    }              
                    regList.add(reg.getName());   
                }
            }
        }
        regsVals = new ArrayList <RegVal> ();
        for (String reg_name: regList) {
            regsVals.add(new RegVal(BigInteger.valueOf(0), false));
            regmodel.addRow(new Object[] {
                reg_name,
                BigInteger.valueOf(0)
            });
        }
        conventionRegs = new ArrayList <Register> ();
       
        var varStorage = program.getCompilerSpec().getDefaultCallingConvention().getPotentialInputRegisterStorage(program);
        for (var storageReg: varStorage) {
            Register reg = storageReg.getRegister();
            if (isV850 || isSparc || reg.isBaseRegister()) {
            	if (!reg.getName().contains("_")) {
            		conventionRegs.add(reg);
            	}
            } 
        }
        regtable = new GhidraTable(regmodel);
        Action action = new AbstractAction() {
            public void actionPerformed(ActionEvent e) {
                TableCellListener tcl = (TableCellListener) e.getSource();
                newVal = (BigInteger) tcl.getNewValue();
                int rowVal = tcl.getRow();
                regsVals.set(rowVal, new RegVal(newVal, true));
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

    public class HexBigIntegerTableCellRenderer extends AbstractGColumnRenderer <BigInteger> {
        protected String formatBigInteger(BigInteger value) {
            return value == null ? "??" : value.toString(16);
        }

        @Override
        public Component getTableCellRendererComponent(GTableCellRenderingData data) {
            super.getTableCellRendererComponent(data);
            setText(formatBigInteger((BigInteger) data.getValue()));
            if (regsVals.get(data.getRowViewIndex()).isEdited == true) {
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
        for (String reg: regList) {
            if (reg.equals(register)) {
                if (!BigInteger.valueOf(address.getOffset()).equals(regsVals.get(counter).value)) {
                    regsVals.set(counter, new RegVal(BigInteger.valueOf(address.getOffset()), true));
                    regtable.setValueAt(BigInteger.valueOf(address.getOffset()), counter, 1);
                    break;
                }
                regsVals.set(counter, new RegVal(BigInteger.valueOf(address.getOffset()), false));
            }
            counter++;
        }
    }

    public static void setRegister(String register, BigInteger value) {
        int counter = 0;
        for (String reg: regList) {
            if (reg.equals(register)) {
                if (!value.equals(regsVals.get(counter).value)) {
                    regsVals.set(counter, new RegVal(value, true));
                    regtable.setValueAt(value, counter, 1);
                    break;
                }
                regsVals.set(counter, new RegVal(value, false));
            }
            counter++;
        }
    }

    public static void setRegister(String register, BigInteger value, boolean isEdited) {
        int counter = 0;
        for (String reg: regList) {
            if (reg.equals(register)) {
                regsVals.set(counter, new RegVal(value, isEdited));
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
            setReturnReg = new DockingAction("Set as link register", getName()) {
                @Override
                public void actionPerformed(ActionContext context) {
                    try {
                        int selected = regtable.getSelectedRow();
                        returnReg = regList.get(selected);
                        JOptionPane.showMessageDialog(null, "Link register (" + returnReg + ") is set!");
                    } catch (Exception ex) {}
                }
            };
            setReturnReg.setToolBarData(new ToolBarData(Icons.ARROW_DOWN_RIGHT_ICON, null));
            setReturnReg.setEnabled(true);
            setReturnReg.markHelpUnnecessary();
            dockingTool.addLocalAction(this, setReturnReg);
            actionsCreated = true;
        }
    }
}
