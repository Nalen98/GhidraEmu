package ghidraemu;

import java.awt.BorderLayout;
import java.awt.Component;
import java.math.BigInteger;
import javax.swing.ImageIcon;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.table.DefaultTableModel;
import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.table.GTableCellRenderingData;
import docking.widgets.table.HexBigIntegerTableCellEditor;
import ghidra.docking.settings.Settings;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.column.AbstractGColumnRenderer;
import resources.Icons;
import resources.ResourceManager;

public class BreakpointProvider extends ComponentProvider {
    private JPanel panel;
    private DockingAction AddBreakAction;
    private DockingAction DelBreakAction;
    public static DefaultTableModel Breakmodel;
    public Program program;
    private static Object[][] breakData = {};
    private static final Object[] columnNames = {"", "Breakpoint"};
    public static GhidraTable breakTable;
    public static ImageIcon BIcon;
    public boolean actionsCreated = false;

    public BreakpointProvider(GhidraEmuPlugin plugin, String pluginName) {
        super(plugin.getTool(), "Breakpoints", pluginName);
        setProgram(program);
        setIcon(ResourceManager.loadImage("images/ico.png"));
        setWindowMenuGroup("GhidraEmu");
    }

    // Customize GUI
    /**
     * @wbp.parser.entryPoint
     */
    private void buildPanel() {
        panel = new JPanel(new BorderLayout());
        BIcon = new ImageIcon(getClass().getResource("/images/breakpoint-enable.png"));
        Breakmodel = new DefaultTableModel(breakData, columnNames) {
            @Override
            public Class < ? > getColumnClass(int column) {
                if (column == 0) return ImageIcon.class;
                return Object.class;
            }
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 1;
            }
        };

        for (Address breakPoint: GhidraEmuProvider.breaks) {
            Breakmodel.addRow(new Object[] {
                BIcon,
                BigInteger.valueOf(breakPoint.getOffset())
            });
        }
        breakTable = new GhidraTable(Breakmodel);
        breakTable.getColumnModel().getColumn(0).setMaxWidth(25);
        breakTable.getColumnModel().getColumn(1).setMinWidth(100);
        breakTable.getColumnModel().getColumn(1).setCellEditor(new HexBigIntegerTableCellEditor());
        breakTable.getColumnModel().getColumn(1).setCellRenderer(new HexBigIntegerTableCellRenderer());
        panel.add(new JScrollPane(breakTable), BorderLayout.CENTER);
        setVisible(true);
    }

    private void createActions() {
        if (!actionsCreated) {
            AddBreakAction = new DockingAction("Add breakpoint", getName()) {
                @Override
                public void actionPerformed(ActionContext context) {
                    AddBreakpointPanel obj = new AddBreakpointPanel();
                    obj.main();
                }
            };
            AddBreakAction.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
            AddBreakAction.setEnabled(true);
            AddBreakAction.markHelpUnnecessary();
            dockingTool.addLocalAction(this, AddBreakAction);

            DelBreakAction = new DockingAction("Delete breakpoint", getName()) {
                @Override
                public void actionPerformed(ActionContext context) {
                    try {
                        int selected = BreakpointProvider.breakTable.getSelectedRow();
                        GhidraEmuPopup.UnSetColor(GhidraEmuProvider.breaks.get(selected));
                        GhidraEmuProvider.breaks.remove(selected);
                        BreakpointProvider.Breakmodel.removeRow(selected);
                    } catch (Exception ex) {}
                }
            };
            DelBreakAction.setToolBarData(new ToolBarData(Icons.DELETE_ICON, null));
            DelBreakAction.setEnabled(true);
            DelBreakAction.markHelpUnnecessary();
            dockingTool.addLocalAction(this, DelBreakAction);
            actionsCreated = true;
        }
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
            return this;
        }

        @Override
        public String getFilterString(BigInteger t, Settings settings) {
            return formatBigInteger(t);
        }
    }
}
