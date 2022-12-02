package ghidraemu;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.border.Border;
import docking.ComponentProvider;
import docking.widgets.label.GLabel;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.plugin.core.function.editor.FunctionEditorModel;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ConsoleService;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.util.ProgramContextImpl;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;


public class GhidraEmuProvider extends ComponentProvider {
    static Program program;
    private JPanel panel;
    public PluginTool tool;
    public GhidraEmuPlugin plugin;
    public static EmulatorHelper emuHelper = null;
    private static final int MALLOC_REGION_SIZE = 0x1000;
    private ArrayList < externalFunction > ImplementedFuncsPtrs;
    private ArrayList < externalFunction > unImplementedFuncsPtrs;
    private ArrayList < externalFunction > ComputedCalls;
    private ArrayList < String > knownFuncs;
    public String originator = "GhidraEmu";
    public Border ClassicBorder;
    public static Address stackStart;
    public Address StopEmu;
    public ConsoleTaskMonitor monitor;
    public ArrayList < Address > traced;
    public static ArrayList < Address > breaks;
    public static JTextField StartTF;
    public static JTextField StopTF;
    public MallocManager mallocMgr;
    private boolean hasHeap;
    public VarnodeContext context;
    public ListingPanel lpanel;

    public GhidraEmuProvider(GhidraEmuPlugin ghidraEmuPlugin, String pluginName) {
        super(ghidraEmuPlugin.getTool(), pluginName, pluginName);
        this.tool = ghidraEmuPlugin.getTool();
        this.plugin = ghidraEmuPlugin;
        setIcon(ResourceManager.loadImage("images/ico.png"));
        setProgram(program);
        setWindowMenuGroup("GhidraEmu");
        traced = new ArrayList < Address > ();
        breaks = new ArrayList < Address > ();
        knownFuncs = new ArrayList < String > (Arrays.asList("malloc", "free", "puts", "strlen"));
    	lpanel = plugin.codeViewer.getListingPanel();
    }

    /**
     * @wbp.parser.entryPoint
     */
    private void buildPanel() {
        panel = new JPanel();
        panel.setMaximumSize(new Dimension(440, 200));

        ImageIcon Starticon = new ImageIcon(getClass().getResource("/images/flag.png"));
        ImageIcon Reseticon = new ImageIcon(getClass().getResource("/images/process-stop.png"));
        ImageIcon Stepicon = new ImageIcon(getClass().getResource("/images/edit-redo.png"));

        JPanel panel_3 = new JPanel();
        JPanel panel_4 = new JPanel();

        JButton StepBtn = new JButton("Step");
        StepBtn.setIcon(Stepicon);
        StepBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                StepEmulation();
            }
        });

        JButton ResetBtn = new JButton("Reset");
        ResetBtn.setIcon(Reseticon);
        ResetBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                Reset();
            }
        });

        JButton RunBtn = new JButton("Run");
        RunBtn.setIcon(Starticon);
        RunBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                RunEmulation();
            }
        });
        GroupLayout gl_panel = new GroupLayout(panel);
        gl_panel.setHorizontalGroup(
        	gl_panel.createParallelGroup(Alignment.TRAILING)
        		.addGroup(gl_panel.createSequentialGroup()
        			.addGap(32)
        			.addComponent(RunBtn, GroupLayout.DEFAULT_SIZE, 96, Short.MAX_VALUE)
        			.addGap(32)
        			.addComponent(StepBtn, GroupLayout.DEFAULT_SIZE, 96, Short.MAX_VALUE)
        			.addGap(32)
        			.addComponent(ResetBtn, GroupLayout.DEFAULT_SIZE, 96, Short.MAX_VALUE)
        			.addGap(66))
        		.addGroup(gl_panel.createSequentialGroup()
        			.addGap(58)
        			.addComponent(panel_3, GroupLayout.DEFAULT_SIZE, 122, Short.MAX_VALUE)
        			.addGap(60)
        			.addComponent(panel_4, GroupLayout.PREFERRED_SIZE, 129, Short.MAX_VALUE)
        			.addGap(81))
        );
        gl_panel.setVerticalGroup(
        	gl_panel.createParallelGroup(Alignment.LEADING)
        		.addGroup(gl_panel.createSequentialGroup()
        			.addGap(22)
        			.addGroup(gl_panel.createParallelGroup(Alignment.LEADING)
        				.addComponent(panel_3, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
        				.addComponent(panel_4, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
        			.addGap(18)
        			.addGroup(gl_panel.createParallelGroup(Alignment.LEADING, false)
        				.addComponent(ResetBtn, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        				.addComponent(StepBtn, 0, 0, Short.MAX_VALUE)
        				.addComponent(RunBtn, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        			.addContainerGap(19, Short.MAX_VALUE))
        );
        GridBagLayout gbl_panel_4 = new GridBagLayout();
        gbl_panel_4.columnWidths = new int[] {
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        };
        gbl_panel_4.rowHeights = new int[] {
            0,
            0,
            0
        };
        gbl_panel_4.columnWeights = new double[] {
            0.0,
            0.0,
            0.0,
            0.0,
            1.0,
            1.0,
            1.0,
            0.0,
            1.0,
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
            Double.MIN_VALUE
        };
        gbl_panel_4.rowWeights = new double[] {
            0.0,
            0.0,
            Double.MIN_VALUE
        };
        panel_4.setLayout(gbl_panel_4);
        GLabel lblNewLabel_1 = new GLabel("Stop");
        GridBagConstraints gbc_lblNewLabel_1 = new GridBagConstraints();
        gbc_lblNewLabel_1.anchor = GridBagConstraints.WEST;
        gbc_lblNewLabel_1.gridwidth = 5;
        gbc_lblNewLabel_1.insets = new Insets(0, 0, 5, 5);
        gbc_lblNewLabel_1.gridx = 6;
        gbc_lblNewLabel_1.gridy = 0;
        panel_4.add(lblNewLabel_1, gbc_lblNewLabel_1);
        StopTF = new JTextField();
        GridBagConstraints gbc_StopTF = new GridBagConstraints();
        gbc_StopTF.anchor = GridBagConstraints.NORTH;
        gbc_StopTF.insets = new Insets(0, 0, 0, 5);
        gbc_StopTF.fill = GridBagConstraints.HORIZONTAL;
        gbc_StopTF.gridwidth = 9;
        gbc_StopTF.gridx = 3;
        gbc_StopTF.gridy = 1;
        gbc_StopTF.weighty = 0.1;
        panel_4.add(StopTF, gbc_StopTF);
        StopTF.addKeyListener(new KeyAdapter() {
            public void keyReleased(KeyEvent e) {
                if (GhidraEmuPopup.stop_address != null) {
                    GhidraEmuPopup.UnSetColor(GhidraEmuPopup.stop_address);
                    GhidraEmuPopup.stop_address = null;
                }
            }
        });
        GridBagLayout gbl_panel_3 = new GridBagLayout();
        gbl_panel_3.columnWidths = new int[] {
            114,
            0
        };
        gbl_panel_3.rowHeights = new int[] {
            15,
            19,
            0
        };
        gbl_panel_3.columnWeights = new double[] {
            1.0,
            Double.MIN_VALUE
        };
        gbl_panel_3.rowWeights = new double[] {
            0.0,
            0.0,
            Double.MIN_VALUE
        };
        panel_3.setLayout(gbl_panel_3);

        GLabel lblNewLabel = new GLabel("Start");
        GridBagConstraints gbc_lblNewLabel = new GridBagConstraints();
        gbc_lblNewLabel.insets = new Insets(0, 0, 5, 0);
        gbc_lblNewLabel.gridx = 0;
        gbc_lblNewLabel.gridy = 0;
        panel_3.add(lblNewLabel, gbc_lblNewLabel);
        StartTF = new JTextField();
        GridBagConstraints gbc_StartTF = new GridBagConstraints();
        gbc_StartTF.anchor = GridBagConstraints.NORTH;
        gbc_StartTF.fill = GridBagConstraints.HORIZONTAL;
        gbc_StartTF.insets = new Insets(0, 0, 0, 5);
        gbc_StartTF.gridx = 0;
        gbc_StartTF.gridy = 1;
        gbc_StartTF.weighty = 0.1;
        panel_3.add(StartTF, gbc_StartTF);
     
        ClassicBorder = StartTF.getBorder();
        StartTF.addKeyListener(new KeyAdapter() {
            public void keyReleased(KeyEvent e) {
                if (GhidraEmuPopup.start_address != null) {
                    GhidraEmuPopup.UnSetColor(GhidraEmuPopup.start_address);
                    GhidraEmuPopup.start_address = null;
                }
            }
        });
        panel.setLayout(gl_panel);
        setVisible(true);
        long stackOffset =
            (program.getMinAddress().getAddressSpace().getMaxAddress().getOffset() >>> 5) - 0x7fff;
        RegisterProvider.setRegister(program.getCompilerSpec().getStackPointer().getName(), getAddressfromLong(stackOffset));
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }

    public void setProgram(Program p) {
        if (p != null) {
            program = p;
            buildPanel();
        }
    }

    public boolean InitEmulation() {
    	if (StartTF.getText().equals("")) {
    		JOptionPane.showMessageDialog(null, "Set start address!");
            return false;
        }    	
        if (StartTF.getText().matches("0x[0-9A-Fa-f]+") == false) {
            return false;
        }
        StartTF.setBorder(ClassicBorder);
        RegisterProvider.setRegister(RegisterProvider.PC, program.getAddressFactory().getAddress(StartTF.getText()));
        try {
            emuHelper = new EmulatorHelper(program);
            monitor = new ConsoleTaskMonitor() {
                @Override
                public void checkCanceled() throws CancelledException {
                    Address address = emuHelper.getExecutionAddress();
                    if (!traced.contains(address)) {
                        traced.add(address);
                        GhidraEmuPopup.SetColor(address, Color.getHSBColor(247, 224, 98));
                    }
                }
            };
            context = new VarnodeContext(program, new ProgramContextImpl(program.getLanguage()), new ProgramContextImpl(program.getLanguage()));

            Address ProgramEntry = program.getMinAddress();
            long stackOffset =
                (ProgramEntry.getAddressSpace().getMaxAddress().getOffset() >>> 5) - 0x7fff;
            Address stackPointer = getAddressfromLong(stackOffset);
            stackStart = getAddressfromLong(stackOffset - 0x1000);

            //set SP register for emulator
            emuHelper.writeRegister(emuHelper.getStackPointerRegister(), stackOffset);

            //update RegisterView with new SP value	
            RegisterProvider.setRegister(emuHelper.getStackPointerRegister().getName(), stackPointer);

            //write stack bytes to emulator after user edititng	
            setEmuStackBytes();

            //Set registers
            setEmuRegisters();

            //write memory bytes to emulator after user edititng	
            setEmuMemory();

            //init heap if we need to
            mallocHandler();

            //library hooks
            getExternalAddresses();
            
            for (externalFunction func: ImplementedFuncsPtrs) {
                emuHelper.setBreakpoint(func.FuncPtr);
            }

            for (externalFunction func: unImplementedFuncsPtrs) {
                emuHelper.setBreakpoint(func.FuncPtr);
            }
            
            for (externalFunction func: ComputedCalls) {
                emuHelper.setBreakpoint(func.FuncPtr);
            }
        } finally {}
        return true;
    }

    public void RunEmulation() {
        if (!StopTF.getText().equals("")) {
            if (StopTF.getText().matches("0x[0-9A-Fa-f]+") == false) {
                return;
            }
            StopTF.setBorder(ClassicBorder);
            StopEmu = program.getAddressFactory().getAddress(StopTF.getText());
        }
        if (emuHelper == null) {
            if (InitEmulation()) {
	            for (Address bp: breaks) {
	                emuHelper.setBreakpoint(bp);
	            }
	            if (!StopTF.getText().equals("")) {
	                emuHelper.setBreakpoint(StopEmu);
	            }
	            Run();
            }
        } else {
            if (!StopTF.getText().equals("")) {
                emuHelper.setBreakpoint(StopEmu);
            }
            for (Address bp: breaks) {
                emuHelper.setBreakpoint(bp);
            }
            setEmuStackBytes();
            setEmuRegisters();
            setEmuMemory();
            Run();
        }
    }
    
    public void StepEmulation() {
        if (emuHelper == null) {
        	if (InitEmulation()) {
        		makeStep();
        	 }
        } else {
            setEmuStackBytes();
            setEmuRegisters();
            setEmuMemory();
            makeStep();
        }
    }

    public static void setEmuStackBytes() {
        byte[] dest = new byte[0x2008];
        try {
            program.getMemory().getBytes(stackStart, dest);
        } catch (MemoryAccessException e) {            
            e.printStackTrace();
        }
        emuHelper.writeMemory(stackStart, dest);
    }

    public static void readStackfromEmu() {
        try {
            int TransactionID = program.startTransaction("UpdateStack");
            program.getMemory().setBytes(stackStart, emuHelper.readMemory(stackStart, 0x2008));
            program.endTransaction(TransactionID, true);
        } catch (MemoryAccessException e) {            
            e.printStackTrace();
        }
        GhidraEmuPlugin.stackprovider.contextChanged();
    }

    public static void setEmuRegisters() {
        int counter = 0;
        for (String reg: RegisterProvider.RegList) {
            try {
                emuHelper.writeRegister(reg, RegisterProvider.RegsVals.get(counter).value);
                counter++;
            } catch (Exception ex) { }
        }
    }

    public static void readEmuRegisters() {
        for (String reg: RegisterProvider.RegList) {
            try {
                RegisterProvider.setRegister(reg, emuHelper.readRegister(reg));
            } catch (Exception ex) {}
        }
    }

    public static void setEmuMemory() {      
    	try {
	        for (var line: GhidraEmuPopup.bytesToPatch) {
	            emuHelper.writeMemory(line.start, line.bytes);
	        }
	        emuHelper.enableMemoryWriteTracking(true);
	    } catch (Exception ex) {};
    }

    public void makeStep() {
        Instruction currentInstruction = program.getListing().getInstructionAt(emuHelper.getExecutionAddress());
        if (currentInstruction == null) {
            JOptionPane.showMessageDialog(null, "Bad Instruction!");
            Reset();
            return;
        }
        boolean success = false;
        try {
            success = emuHelper.step(monitor);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(null, e.getStackTrace());
            Reset();
            return;
        }
        Address executionAddress = emuHelper.getExecutionAddress();
        if (!success) {
        	String lastError = emuHelper.getLastError();
        	readStackfromEmu();
            readEmuRegisters();
            GhidraEmuPopup.bytesToPatch.clear();
            JOptionPane.showMessageDialog(null, lastError);
        }
        GhidraEmuPopup.SetColor(executionAddress, Color.getHSBColor(247, 224, 98));
        traced.add(executionAddress);
        try {
            ProgramLocation location = new ProgramLocation(program, executionAddress);
            lpanel.scrollTo(location);
        } 
        catch (Exception ex) {}
        readStackfromEmu();
        readEmuRegisters();

        GhidraEmuPopup.bytesToPatch.clear();

        if (emuHelper.readRegister(emuHelper.getPCRegister()) == BigInteger.valueOf(0)) {
            emuHelper.dispose();
            emuHelper = null;
            JOptionPane.showMessageDialog(null, "Emulation finished!");
            return;
        }
        processBreakpoint(executionAddress);
    }

    public void Run() {
        Instruction currentInstruction = program.getListing().getInstructionAt(emuHelper.getExecutionAddress());
        if (currentInstruction == null) {
            JOptionPane.showMessageDialog(null, "Bad Instruction!");
            Reset();
            return;
        }
        boolean success = false;
        try {
            success = emuHelper.run(monitor);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(null, e.getStackTrace());
            Reset();
            return;
        }
        Address executionAddress = emuHelper.getExecutionAddress();
        if (executionAddress.getOffset() == 0) {
            GhidraEmuPopup.bytesToPatch.clear();
            readStackfromEmu();
            readEmuRegisters();
            ProgramLocation location = new ProgramLocation(program, traced.get(traced.size()-1));
            lpanel.scrollTo(location);
            emuHelper.dispose();
            emuHelper = null;
            JOptionPane.showMessageDialog(null, "Emulation finished!");
            return;
        }        
        if (!success) {
            String lastError = emuHelper.getLastError();
            readStackfromEmu();
            readEmuRegisters();
            GhidraEmuPopup.bytesToPatch.clear();
            JOptionPane.showMessageDialog(null, lastError);
            return;
        }
        traced.add(executionAddress);
        ProgramLocation location = new ProgramLocation(program, executionAddress);
        lpanel.scrollTo(location);
        readStackfromEmu();
        readEmuRegisters();
        GhidraEmuPopup.bytesToPatch.clear();

        if (emuHelper.readRegister(emuHelper.getPCRegister()) == BigInteger.valueOf(0)) {
            emuHelper.dispose();
            emuHelper = null;
            GhidraEmuPopup.UnSetColor(emuHelper.getExecutionAddress());
            JOptionPane.showMessageDialog(null, "Emulation finished!");
            return;
        }
        if (processBreakpoint(executionAddress)) {
            Run();
        }
        else {
            GhidraEmuPopup.SetColor(executionAddress, Color.orange);
        }
    }

    public boolean processBreakpoint(Address addr) {
        if (addr.equals(StopEmu)) {
            emuHelper.dispose();
            emuHelper = null;
            JOptionPane.showMessageDialog(null, "Emulation finished!");
            return false;
        }
        for (externalFunction func: ImplementedFuncsPtrs) {
            if (addr.equals(func.FuncPtr)) {
                EmulateKnownFunc(func);
                IPback();
                return true;
            }
        }
        for (externalFunction func: unImplementedFuncsPtrs) {
            if (addr.equals(func.FuncPtr)) {
                plugin.console.addMessage(originator, "Unimplemented function " + func.function.getName() + "!");
                IPback();
                return true;
            }
        }        
        for (externalFunction func: ComputedCalls) {
            if (addr.equals(func.FuncPtr)) {
                GhidraEmuPopup.SetColor(addr, Color.getHSBColor(247, 224, 98));
                for (externalFunction unImplfunc: unImplementedFuncsPtrs) {
                    if (unImplfunc.function.equals(func.function)) {
                        plugin.console.addMessage(originator, "Call intercepted — " + func.function.getName() + ".");
                        emuHelper.writeRegister(RegisterProvider.PC, program.getListing().getInstructionAt(emuHelper.getExecutionAddress()).getNext().getAddress().getOffset());
                        RegisterProvider.setRegister(RegisterProvider.PC, emuHelper.readRegister(RegisterProvider.PC));
                        return true;
                    }
                }                
                for (externalFunction Implfunc: ImplementedFuncsPtrs) {
                    if (Implfunc.function.equals(func.function)) {
                        EmulateKnownFunc(func);
                        emuHelper.writeRegister(RegisterProvider.PC, program.getListing().getInstructionAt(emuHelper.getExecutionAddress()).getNext().getAddress().getOffset());
                        RegisterProvider.setRegister(RegisterProvider.PC, emuHelper.readRegister(RegisterProvider.PC));
                        return true;
                    }
                }                
            }
        }
        for (Address bp: breaks) {
            if (addr.equals(bp)) {
                GhidraEmuPopup.SetColor(bp, Color.getHSBColor(247, 224, 98));
                return false;
            }
        }
        return false;
    }

    public void Reset() {
        //Registers zeroed
        for (String reg: RegisterProvider.RegList) {
            try {
                RegisterProvider.setRegister(reg, BigInteger.valueOf(0), false);
            } catch (Exception ex) {}
        }
        //Stack zeroed
        if (stackStart != null) {
            try {
                int TransactionID = program.startTransaction("UpdateStack");
                program.getMemory().setBytes(stackStart, new byte[0x2008]);
                program.endTransaction(TransactionID, true);
                GhidraEmuPlugin.stackprovider.contextChanged();
            } catch (MemoryAccessException e) {                
                e.printStackTrace();
            }
        }
        //Zero fields
        if (GhidraEmuPopup.start_address != null) {
            GhidraEmuPopup.UnSetColor(GhidraEmuPopup.start_address);
            GhidraEmuPopup.start_address = null;
        }
        if (GhidraEmuPopup.stop_address != null) {
            GhidraEmuPopup.UnSetColor(GhidraEmuPopup.stop_address);
            GhidraEmuPopup.stop_address = null;
        }
        StartTF.setText("");
        StopTF.setText("");
        for (Address colorAddress: traced) {
            GhidraEmuPopup.UnSetColor(colorAddress);
        }
        traced.clear();
        for (Address bp: breaks) {
            GhidraEmuPopup.UnSetColor(bp);
        }
        RegisterProvider.returnReg = null;
        breaks.clear();
        BreakpointProvider.Breakmodel.setRowCount(0);
        BreakpointProvider.breakTable.repaint();
        try {
            emuHelper.dispose();
        } 
        catch (Exception ex) {}
        emuHelper = null;
        plugin.console.clearMessages();
    }
    
    public void getExternalAddresses() {
        ImplementedFuncsPtrs = new ArrayList < externalFunction > ();
        unImplementedFuncsPtrs = new ArrayList < externalFunction > ();
        ComputedCalls = new ArrayList < externalFunction >();
        for (Symbol externalSymbol: program.getSymbolTable().getExternalSymbols()) {
            if (externalSymbol != null && externalSymbol.getSymbolType() == SymbolType.FUNCTION) {
                Function f = (Function) externalSymbol.getObject();
                Address[] thunkAddrs = f.getFunctionThunkAddresses();
                if (thunkAddrs == null) {
                    //If symbol is not a thunk function it will be null, precedent was noticed in windows binaries
                    Reference[] references = externalSymbol.getReferences();
                    for (Reference ref : references) {
                        RefType refType = ref.getReferenceType();
                        Address ptrToFunc = ref.getFromAddress();
                        if (refType == RefType.DATA) { 
                            if (knownFuncs.contains(f.getName())) {
                                ImplementedFuncsPtrs.add(new externalFunction(ptrToFunc, f));
                            } else {
                                unImplementedFuncsPtrs.add(new externalFunction(ptrToFunc, f));
                            }
                        } else if (refType == RefType.COMPUTED_CALL) {  
                            ComputedCalls.add(new externalFunction(ptrToFunc, f));
                        }
                    }
                }
                else {
                    if (thunkAddrs.length == 1) {
                        if (knownFuncs.contains(f.getName())) {
                            ImplementedFuncsPtrs.add(new externalFunction(thunkAddrs[0], f));
                        } else {
                            unImplementedFuncsPtrs.add(new externalFunction(thunkAddrs[0], f));
                        }
                    }
                }
            }
        }
    }

    public boolean checkForMalloc() {
        Symbol externalSymbol = program.getSymbolTable().getExternalSymbol("malloc");
        if (externalSymbol == null) {
            return false;
        }
        return true;
    }

    public void IPback() {
        try {
            if (program.getLanguage().getProcessor().toString().equals("AARCH64")) {
                emuHelper.writeRegister(RegisterProvider.PC, emuHelper.readRegister("x30"));
            } else if (program.getLanguage().getProcessor().toString().toLowerCase().contains("mips")) {
                emuHelper.writeRegister(RegisterProvider.PC, emuHelper.readRegister("ra"));
            } else if (RegisterProvider.RegList.contains("LR")) {
                emuHelper.writeRegister(RegisterProvider.PC, emuHelper.readRegister("LR"));
            } else if (RegisterProvider.RegList.contains("lr")) {
                emuHelper.writeRegister(RegisterProvider.PC, emuHelper.readRegister("lr"));
            } else if (RegisterProvider.returnReg != null) {
                emuHelper.writeRegister(RegisterProvider.PC, emuHelper.readRegister(RegisterProvider.returnReg));
            } else {
                emuHelper.writeRegister(RegisterProvider.PC, emuHelper.readStackValue(0, 8, false));
            }
            RegisterProvider.setRegister(RegisterProvider.PC, emuHelper.readRegister(RegisterProvider.PC));
        } catch (Exception e) {            
            e.printStackTrace();
        }
    }

    public void mallocHandler() {
        //If there's malloc func -> gonna get a heap
        if (checkForMalloc()) {
            Address heapAddr = getAddressfromInt(0x70000000);
            //Check if Heap was Initialized
            for (MemoryBlock block: program.getMemory().getBlocks()) {
                if (block.getName().equals("Heap")) {
                    hasHeap = true;
                    break;
                }
            }
            if (!hasHeap) {
                //mmap heap
                try {
                    int TransactionID = program.startTransaction("Mapping Heap");
                    MemoryBlock newBlock = program.getMemory().createInitializedBlock("Heap", heapAddr, MALLOC_REGION_SIZE, (byte) 0,
                        TaskMonitor.DUMMY, false);
                    newBlock.setPermissions(true, true, true);
                    program.endTransaction(TransactionID, true);
                } catch (LockException | IllegalArgumentException | MemoryConflictException |
                    AddressOverflowException | CancelledException e) {                    
                    e.printStackTrace();
                }
                plugin.console.addMessage(originator, "Heap allocated at 0x70000000. If you need more space go to Memory Map.");
            }
            try {
                mallocMgr = new MallocManager(heapAddr, MALLOC_REGION_SIZE);
            } catch (AddressOverflowException e) {                
                e.printStackTrace();
            }
        }
    }

    public static class externalFunction {
        public Address FuncPtr;
        public Function function;

        externalFunction(Address FuncPtr, Function
            function) {
            this.FuncPtr = FuncPtr;
            this.function = function;
        }
    }
    
    private Address getAddressfromInt(int offset) {
        return program.getAddressFactory().getAddress(Integer.toHexString(offset));
    }
    
    private Address getAddressfromLong(long offset) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }
    
    public void EmulateKnownFunc(externalFunction func) {
        if (func.function.getName().contains("malloc")) {
            int size = emuHelper.readRegister(RegisterProvider.ConventionRegs.get(0)).intValue();
            Address memAddr = null;
            try {
                memAddr = mallocMgr.malloc(size);
            } catch (InsufficientBytesException e) {                
                e.printStackTrace();
            }

            FunctionEditorModel model = new FunctionEditorModel(null, func.function);
            Register returnReg = model.getReturnStorage().getRegister();

            emuHelper.writeRegister(returnReg, memAddr.getOffset());
            RegisterProvider.setRegister(returnReg.getName(), memAddr);
        }  else if (func.function.getName().contains("free")) {            
            Address freeAddr = program.getAddressFactory().getAddress(emuHelper.readRegister(RegisterProvider.ConventionRegs.get(0)).toString(16));
            mallocMgr.free(freeAddr);
        }  else if (func.function.getName().contains("puts")) {
            String address = emuHelper.readRegister(RegisterProvider.ConventionRegs.get(0)).toString(16);
            Address string = program.getAddressFactory().getAddress(address);
            plugin.console.addMessage(originator, emuHelper.readNullTerminatedString(string, 0x1000));
        } else if (func.function.getName().contains("strlen")) {
            Address ptr = program.getAddressFactory().getAddress(emuHelper.readRegister(RegisterProvider.ConventionRegs.get(0)).toString(16));
            int len = 0;
            while (emuHelper.readMemoryByte(ptr) != 0) {
                ++len;
                ptr = ptr.next();
            }            
            FunctionEditorModel model = new FunctionEditorModel(null, func.function);
            Register returnReg = model.getReturnStorage().getRegister();
            emuHelper.writeRegister(returnReg, len);
            RegisterProvider.setRegister(returnReg.getName(), BigInteger.valueOf(len));
        }
    }
}
