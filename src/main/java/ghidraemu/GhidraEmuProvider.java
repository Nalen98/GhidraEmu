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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingWorker;
import javax.swing.border.Border;

import docking.ComponentProvider;
import docking.widgets.label.GLabel;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.emulate.EmulateExecutionState;
import ghidra.pcode.memstate.MemoryFaultHandler;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.ProgramContextImpl;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;


public class GhidraEmuProvider extends ComponentProvider {    
    public static final String originator = "GhidraEmu";
    public static final String successMsg = "Emulation finished!";
    public static final String unknowPC = "Unknow PC!";
    public static final String badInsn = "Bad Instruction!";
    public static final String sthWrong = "Check out your emulation options, something wrong!";
    public static final int MALLOC_REGION_SIZE = 0x1000;          
    public static ArrayList <Address> breaks;
    public static EmulatorHelper emuHelper;
    public static HashMap<Address, Integer> addressesToUpdate;
    public static HashMap<Address, Integer> userBytes;
    public static HashMap<Address, byte[]> origBytes;
    public static JTextField startTF;
    public static JTextField stopTF;       
    public static Program program;    
    public Map<String, List<String>> delayedBranchInsns;    
    public Address stepOverToAddr;
    public CopyOnWriteArrayList <Address> traced;
    public EmuRun sw;
    public PluginTool tool;
    public GhidraEmuPlugin plugin;
    public Border classicBorder;    
    public Address stopEmu;
    public ConsoleTaskMonitor monitor;        
    public MallocManager mallocMgr;    
    public VarnodeContext context;
    public ListingPanel lpanel;
    public List<FileBytes> binBytes;    
    public int stackSize;
    public Address stackPointer;
    public Address stackStart;
    public ProgramLocation endLocation;
    public String message;
    public String processorName;
    public String stackName;    
    public boolean isStateClear;
    public boolean isDirty;
    public boolean hasBranchDelaySlot;
    private boolean hasHeap;
    private ArrayList <ExternalFunction> implementedFuncsPtrs;
    private ArrayList <ExternalFunction> unimplementedFuncsPtrs;
    private ArrayList <ExternalFunction> computedCalls;
    private ArrayList <String> knownFuncs;    
    private JPanel panel;

    public GhidraEmuProvider(GhidraEmuPlugin ghidraEmuPlugin, String pluginName) {
        super(ghidraEmuPlugin.getTool(), pluginName, pluginName);
        this.tool = ghidraEmuPlugin.getTool();
        this.plugin = ghidraEmuPlugin;
        setIcon(ResourceManager.loadImage("images/ico.png"));
        setProgram(program);
        setWindowMenuGroup("GhidraEmu");
        traced = new CopyOnWriteArrayList <Address> ();
        breaks = new ArrayList <Address> ();
        addressesToUpdate = new HashMap<Address, Integer>();
        userBytes = new HashMap<Address, Integer>();
        origBytes = new HashMap<Address, byte[]>();     
        delayedBranchInsns = Map.of("superh", Arrays.asList("jsr"),
                                    "mips", Arrays.asList("jr", "jalr", "b", "beq", "bne", "bnel", "bnez", 
                                                        "beql", "beqz", "blt", "bltu", "bltz", "ble", "bleu", "blez",
                                                        "bge", "bgeu", "bgez", "bgezal", "bgt", "bgtu", "bgtz", "bczt", 
                                                        "bczf", "bltzal"),
                                    "sparc",  Arrays.asList("bpa", "bpn", "bpne", "bpe", "bpg", "bple", "bpge", "bpl", 
                                                            "bpgu", "bpleu", "bpcc", "bpcs", "bppos", "bpneg", "bpvs", 
                                                            "brz", "brlez", "brlz", "brnz", "brgz", "brgez", "ret", "call"));                										
        knownFuncs = new ArrayList <String> (Arrays.asList("malloc", "free", "puts", "strlen", "exit"));
        lpanel = plugin.codeViewer.getListingPanel();    	
        emuHelper = null;
        isStateClear = true;
        isDirty = false;
    }
    
    public class ExternalFunction {
        public Address funcPtr;
        public Function function;

        ExternalFunction(Address funcPtr, Function function) {
            this.funcPtr = funcPtr;
            this.function = function;
        }
    }

    public class EmuRun extends SwingWorker<Void, String> {
        public ArrayList <Address> painted = new  ArrayList <Address>();
        public ArrayList <String> printedMessages = new  ArrayList <String>();

        @Override
        protected Void doInBackground() throws Exception { 
            runEmulation();
            return null;
        }

        @Override
        protected void process(List <String> msgs) {
            HashSet<String> hset = new HashSet<String>(msgs);
            hset.remove(null);
            hset.removeAll(printedMessages);
            if (!hset.isEmpty()) {
            // Compare two HashSets - the new one and messages
            // If something was added - print
                for (String msg : hset) {
                    plugin.console.addMessage(originator, msg);
                    printedMessages.add(msg);
                }
            }
            
            List<Address> toPaint= traced.stream().distinct().collect(Collectors.toList());
            toPaint.removeAll(painted);
            if (!toPaint.isEmpty()) {
                for (Address addr : toPaint){
                    GhidraEmuPopup.setColor(addr, Color.getHSBColor(247, 224, 98));
                    painted.add(addr);
                }
            }                      
            
            readEmuRegisters();
            if (isCancelled()) {
                return;
            }
        }
    
        @Override
        protected void done() {
            if (isDirty) {
                return;
            }
            if (endLocation != null){
                try {
                    lpanel.scrollTo(endLocation);
                    GhidraEmuPopup.setColor(endLocation.getAddress(), Color.orange);
                }
                catch (Exception ex) {};
            }    
            if (addressesToUpdate != null){
                for (Address start : addressesToUpdate.keySet()){
                    updatePtrUnstable(start);
                }
            }           
            if (message != null){
                if (painted != null) {
                    painted.clear(); 
                }    
                if (printedMessages != null) {
                    printedMessages.clear();
                }
                JOptionPane.showMessageDialog(null, message);
            }
        }   
        
        public void publishWrap(String msg) {
            publish(msg);
        }
    }
    
    private void buildPanel() {
        panel = new JPanel();
        panel.setMaximumSize(new Dimension(440, 200));

        ImageIcon startIcon = new ImageIcon(getClass().getResource("/images/flag.png"));
        ImageIcon resetIcon = new ImageIcon(getClass().getResource("/images/process-stop.png"));
        ImageIcon stepIcon = new ImageIcon(getClass().getResource("/images/edit-redo.png"));

        JPanel panel_3 = new JPanel();
        JPanel panel_4 = new JPanel();

        JButton stepBtn = new JButton("Step");
        stepBtn.setIcon(stepIcon);
        stepBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                if (sw == null) {
                    stepEmulation();
                } else {
                    if (sw.isDone() || sw.isCancelled()) {
                        stepEmulation();
                    }
                }
            }
        });
        
        JButton runBtn = new JButton("Run");       
        runBtn.setIcon(startIcon);             
        runBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                sw = new EmuRun();  
                sw.execute();
            }
        });

        
        JButton resetBtn = new JButton("Reset");
        resetBtn.setIcon(resetIcon);
        resetBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {  
                if (sw == null){
                    resetState();
                }
                else {
                    if (!sw.isDone()){
                        sw.cancel(true);
                    }
                    if (sw.isCancelled() || sw.isDone()){
                        resetState();
                    }
                }            
            }
        });
        
        GroupLayout gl_panel = new GroupLayout(panel);
        gl_panel.setHorizontalGroup(
            gl_panel.createParallelGroup(Alignment.TRAILING)
                .addGroup(gl_panel.createSequentialGroup()
                    .addGap(8)
                    .addComponent(runBtn, GroupLayout.DEFAULT_SIZE, 60, Short.MAX_VALUE)
                    .addGap(10)
                    .addComponent(stepBtn, GroupLayout.DEFAULT_SIZE, 60, Short.MAX_VALUE)
                    .addGap(10)
                    .addComponent(resetBtn, GroupLayout.DEFAULT_SIZE, 60, Short.MAX_VALUE)
                    .addGap(26))
                .addGroup(gl_panel.createSequentialGroup()
                    .addGap(21)
                    .addComponent(panel_3, GroupLayout.PREFERRED_SIZE, 109, Short.MAX_VALUE)
                    .addGap(60)
                    .addComponent(panel_4, GroupLayout.PREFERRED_SIZE, 109, Short.MAX_VALUE)                    
                    .addGap(31))
        );
        gl_panel.setVerticalGroup(
            gl_panel.createParallelGroup(Alignment.LEADING)
                .addGroup(gl_panel.createSequentialGroup()
                    .addGap(10)
                    .addGroup(gl_panel.createParallelGroup(Alignment.LEADING)
                        .addComponent(panel_3, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                        .addComponent(panel_4, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                    .addGap(18)
                    .addGroup(gl_panel.createParallelGroup(Alignment.LEADING, false)
                        .addComponent(resetBtn, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(stepBtn, 0, 0, Short.MAX_VALUE)
                        .addComponent(runBtn, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
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
        stopTF = new JTextField();
        GridBagConstraints gbc_stopTF = new GridBagConstraints();
        gbc_stopTF.anchor = GridBagConstraints.NORTH;
        gbc_stopTF.insets = new Insets(0, 0, 0, 5);
        gbc_stopTF.fill = GridBagConstraints.HORIZONTAL;
        gbc_stopTF.gridwidth = 9;
        gbc_stopTF.gridx = 3;
        gbc_stopTF.gridy = 1;
        gbc_stopTF.weighty = 0.1;
        panel_4.add(stopTF, gbc_stopTF);
        stopTF.addKeyListener(new KeyAdapter() {
            public void keyReleased(KeyEvent e) {
                if (GhidraEmuPopup.stop_address != null) {
                    GhidraEmuPopup.unsetColor(GhidraEmuPopup.stop_address);
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
        startTF = new JTextField();
        GridBagConstraints gbc_startTF = new GridBagConstraints();
        gbc_startTF.anchor = GridBagConstraints.NORTH;
        gbc_startTF.fill = GridBagConstraints.HORIZONTAL;
        gbc_startTF.insets = new Insets(0, 0, 0, 5);
        gbc_startTF.gridx = 0;
        gbc_startTF.gridy = 1;
        gbc_startTF.weighty = 0.1;
        panel_3.add(startTF, gbc_startTF);
    
        classicBorder = startTF.getBorder();
        startTF.addKeyListener(new KeyAdapter() {
            public void keyReleased(KeyEvent e) {
                if (GhidraEmuPopup.start_address != null) {
                    GhidraEmuPopup.unsetColor(GhidraEmuPopup.start_address);
                    GhidraEmuPopup.start_address = null;
                }
            }
        });
        panel.setLayout(gl_panel);
        setVisible(true);        
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

    public boolean updateStopEmu(){
        // get end address
        if (!stopTF.getText().equals("")) {
            if (stopTF.getText().matches("0x[0-9A-Fa-f]+") == false) {
                JOptionPane.showMessageDialog(null, "Set the correct address!");
                return false;
            }
            stopTF.setBorder(classicBorder);
            stopEmu = getAddressFromString(stopTF.getText());
        } else {
            // non stop emulation
            stopEmu = null;
        }
        return true;
    }

    public void interrupt(Address pc, Address address, String errMsg) {
        Boolean isRunning = null;
        if (sw == null ) {
            isRunning = false;
        } else {
            if (!sw.isDone() && !sw.isCancelled()) {                
                isRunning = true;
            } else {
                isRunning = false;
            }
        }    
        
        // Let's try to give this instruction a chance again 
        // if the address refers to an existing memory area
        if (address != null) {
            for (MemoryBlock block : program.getMemory().getBlocks()){
                if (block.contains(address)) {  
                    if (!block.isInitialized()) {
                        int transactionID = -1;
                        try {
                            transactionID = program.startTransaction("Initialize the memory block");
                            program.getMemory().convertToInitialized(block, (byte) 0);                               
                        } catch (Exception ex){
                            ex.printStackTrace();
                        } finally {       
                            program.endTransaction(transactionID, true);
                            plugin.console.addMessage(originator, "The memory block " + block.getName() + " was successfully initialized!");                           
                        }                       
                        return;
                    } else {
                        // Yes, oddities still occur. Let's skip it
                        return;
                    }
                }
            }
        }
        if (isRunning) {
            if (!sw.isCancelled()){
                sw.publishWrap(errMsg);
            }
        } else {
            plugin.console.addMessage(originator, errMsg);
        }
        
        
        // Update the emulation context before exit
        readEmuRegisters();
        readMemFromEmu(isRunning);
        // Exit
        message = sthWrong;
        stopEmulationLight(pc, isRunning);
    }
    
    public void addTracedIfNotLast(Address address){
        // To avoid duplicates
        if (!traced.isEmpty()){
            Address lastAddr = traced.get(traced.size()-1);
            if (!lastAddr.equals(address)){
                traced.add(address);
            }
        } else {
            traced.add(address);
        }           
    }

    public Instruction getNextIfDelaySlot(Instruction currentInstruction){    
        // for branch delay slot
        String mnemonic = currentInstruction.getMnemonicString().toLowerCase();
        for (Map.Entry<String, List<String>> entry : delayedBranchInsns.entrySet()) {
            String proc = entry.getKey();
            if (processorName.toLowerCase().contains(proc)){
                List<String> insns = entry.getValue();
                for (String instruction : insns){
                    if (mnemonic.contains(instruction)){
                        return currentInstruction.getNext();
                    }
                }
            }
        }
        return null;
    }

    public boolean initEmulation() {      
        if (!isStateClear){
            // It's a dirty start, user didn't press "Reset" before start
            JOptionPane.showMessageDialog(null, "Reset the previous emulation state!");
            return false;
        } 
        // get start address
        if (startTF.getText().equals("")) {
            JOptionPane.showMessageDialog(null, "Set start address!");
            return false;
        }    	
        if (startTF.getText().matches("0x[0-9A-Fa-f]+") == false) {
            JOptionPane.showMessageDialog(null, "Set the correct address!");
            return false;
        }
        startTF.setBorder(classicBorder); 
        if (!updateStopEmu()){
            return false;
        }       
        Address start = getAddressFromString(startTF.getText());
        RegisterProvider.setRegister(RegisterProvider.PC, start);
        traced.add(start);
        GhidraEmuPopup.setColor(start, Color.getHSBColor(247, 224, 98));
        
        MemoryFaultHandler memFaultHandler = new MemoryFaultHandler() {
            @Override
            public boolean uninitializedRead(Address address, int size, byte[] buf, int bufOffset) {
                if (emuHelper.getEmulateExecutionState() == EmulateExecutionState.INSTRUCTION_DECODE) {
                    return false;
                }
                
                Address pc = emuHelper.getExecutionAddress();               
                Register reg = program.getRegister(address, size);
                if (reg != null) {
                    String badRegErr = "Uninitialized register READ at " + pc + ": " + reg;
                    interrupt(pc, address, badRegErr);
                    return true;
                }
                String badMemErr ="Uninitialized memory READ at pc = " + pc + " to address = " + address.toString(true) + " with size = " + size;
                interrupt(pc, address, badMemErr);
                return true;
            }

            @Override
            public boolean unknownAddress(Address address, boolean write) {
                Address pc = emuHelper.getExecutionAddress();
                String access = write ? "written" : "read";
                String errMsg = "Unknown address " + access + " at " + pc + ": " + address;
                interrupt(pc, address, errMsg);
                return false;
            }
        };
        
        try {
            emuHelper = new EmulatorHelper(program);
            emuHelper.setMemoryFaultHandler(memFaultHandler);
            emuHelper.enableMemoryWriteTracking(true);
            monitor = new ConsoleTaskMonitor() {
                @Override
                public void checkCanceled() throws CancelledException {
                    if (sw != null && !sw.isCancelled() && !sw.isDone()){
                        // just running
                        Address pc = emuHelper.getExecutionAddress();
                        Instruction currentInstruction = program.getListing().getInstructionAt(pc);
                        if (currentInstruction == null){
                            interrupt(pc, null, badInsn);
                            return;
                        }                      
                        addTracedIfNotLast(pc);

                        // delayed branch instructions painting (SuperH, MIPS, Sparc)
                        if (hasBranchDelaySlot){
                            Instruction nextInsn = getNextIfDelaySlot(currentInstruction);                       
                            if (nextInsn != null){
                                Address execBefore = nextInsn.getAddress();
                                addTracedIfNotLast(execBefore);
                            }
                        }
                        sw.publishWrap(null);
                    }
                }
            };
            context = new VarnodeContext(program, new ProgramContextImpl(program.getLanguage()), new ProgramContextImpl(program.getLanguage()));
            message = null;
            endLocation = null;     
            
            // get processor name
            processorName = program.getLanguage().getProcessor().toString();

            // RISC architectures that each have a single branch delay slot
            hasBranchDelaySlot = processorName.toLowerCase().contains("v850") ||
                processorName.toLowerCase().contains("mips") || 
                    processorName.toLowerCase().contains("sparc");
            
            boolean is8051 = processorName.equalsIgnoreCase("8051");
            if (is8051) {
                stackName = "REG_BANK_1";
            } else {
                for (MemoryBlock block : program.getMemory().getBlocks()) {
                    String blockName = block.getName();
                    if (blockName.toLowerCase().contains("stack")) {
                        stackName = blockName;
                        break;
                    }
                }
            }
            
            stackStart = program.getMemory().getBlock(stackName).getStart();
            stackSize = (int)program.getMemory().getBlock(stackName).getSize();
            stackPointer = stackStart.add(stackSize/2);
            long stackPointerAsLong = stackPointer.getAddressableWordOffset();
            if (processorName.equalsIgnoreCase("v850") || processorName.equalsIgnoreCase("sparc")){
                stackPointerAsLong = 0xFFFFFFFF;
            }
            if (is8051){
                stackSize = 0x100;
                stackPointerAsLong = 0x8;
                stackPointer = getAddressFromString("INTMEM:08");
            }
            
            //save FileBytes to restore the original bytes of the binary changed by user (experimental)
            binBytes = program.getMemory().getAllFileBytes();             
        
            //set SP register for emulator         
            emuHelper.writeRegister(emuHelper.getStackPointerRegister(), stackPointerAsLong);

            //update RegisterView with new SP value	            
            RegisterProvider.setRegister(emuHelper.getStackPointerRegister().getName(), stackPointer);
            
            //set registers
            setEmuRegisters();

            //set stack bytes
            setEmuStackBytes();

            //set patched bytes
            setEmuMemory();

            //init heap if we need to
            mallocHandler();

            //library hooks
            getExternalAddresses();
            
            for (ExternalFunction func: implementedFuncsPtrs) {
                emuHelper.setBreakpoint(func.funcPtr);
            }

            for (ExternalFunction func: unimplementedFuncsPtrs) {
                emuHelper.setBreakpoint(func.funcPtr);
            }
            
            for (ExternalFunction func: computedCalls) {
                emuHelper.setBreakpoint(func.funcPtr);
            }
        } finally {}
        return true;
    }

    public void runEmulation() {   
        boolean isFirstLaunch = false;     
        if (emuHelper == null) {
            if (!initEmulation()){
                isDirty = true;
                return;
            }
            isDirty = false;
            isFirstLaunch = true;
        }   
        for (Address bp: breaks) {
            emuHelper.setBreakpoint(bp);
        }
        if (!updateStopEmu()){
            return;
        }
        if (stopEmu != null) {
            emuHelper.setBreakpoint(stopEmu);
        }
        if (!isFirstLaunch){
            setEmuRegisters();
            setEmuStackBytes();
            setEmuMemory();
        }       
        Run(); 
    }
    
    public void stepEmulation() {
        if (emuHelper == null) {
            if (initEmulation()) {
                makeStep();
            }
        } else {
            if (!updateStopEmu()){
                return;
            }
            setEmuRegisters();
            setEmuStackBytes();
            setEmuMemory();
            makeStep();
        }
    }

    public void readEmuRegisters() {
        for (String reg: RegisterProvider.regList) {
            try {
                RegisterProvider.setRegister(reg, emuHelper.readRegister(reg));
            } catch (Exception ex) {}
        }
    }

    public boolean readMemFromEmu(boolean isRunning) {        
        AddressSetView changedAddresses =  emuHelper.getTrackedMemoryWriteSet();           	
        for (AddressRange addressSet : changedAddresses) {    		
            Address start = addressSet.getMinAddress();    		
            int len = (int) addressSet.getLength();            
            if (addrBelongsToMem(start) || start.getAddressSpace().getName().equalsIgnoreCase("ram")) {
                boolean isEnoughSpace = false;
                while (!isEnoughSpace){
                    if (!program.getMemory().getBlock(stackName).contains(start) && !origBytes.containsKey(start)){                    	
                        byte [] beforeChange = new byte[len];
                        int transactionSB = program.startTransaction("SaveOrigBytes");                            
                        try {
                            program.getMemory().getBytes(start, beforeChange);
                            origBytes.put(start, beforeChange); 
                            isEnoughSpace = true;
                        } catch (MemoryAccessException e) {								 
                            e.printStackTrace();

                            // Check - is it stack just wants to expand its ranges or we're dealing with uninitialized memory							
                            if (e.getMessage().contains("Unable to read bytes at ram")){
                                
                                // Check if not enough stack is allocated     
                                String conflictAddressStr = e.getMessage().substring(e.getMessage().indexOf("ram:") + 4);
                                Address conflictAddress = getAddressFromString(conflictAddressStr);   
                                Address deadLine = stackStart.subtract(0x1000);
                                int cmp1 = conflictAddress.compareTo(stackStart);
                                int cmp2 = conflictAddress.compareTo(deadLine);
                                if  (cmp1 <= 0 && cmp2 >= 0) {
                                    // set more space for stack
                                    MemoryBlock expandBlock = program.getMemory().getBlock(stackName);
                                    Memory memory = program.getMemory();
                                    MemoryBlock newBlock;		      
                                    int transactionID = program.startTransaction("MappingStack"); 
                                    try {
                                        stackSize = stackSize + 0x1000;
                                        stackStart = stackStart.subtract(0x1000);
                                        newBlock = memory.createInitializedBlock(stackName, 
                                            stackStart, 0x1000, (byte) 0, TaskMonitor.DUMMY, false);
                                        memory.join(newBlock, expandBlock);
                                    } catch (Exception ex) {	
                                        ex.printStackTrace();
                                        handleError(isRunning, ex);	
                                        return false;	                                   
                                    }  finally {
                                        program.endTransaction(transactionID, true);			                                    
                                    }
                                } else {
                                    // Uninitialized memory access
                                    // Check that addresses are inside the program space
                                    // The plugin will not create new program blocks (if it's not a stack)
                                    boolean isInSpace = false;                                   
                                    for (MemoryBlock block : program.getMemory().getBlocks()){
                                        if (block.contains(start)) {                                    		
                                            isInSpace = true;
                                            // you can bet it's ".bss"
                                            if (!block.isInitialized()) {
                                                int transactionID = -1;
                                                try {
                                                    transactionID = program.startTransaction("Init_bytes");
                                                    program.getMemory().convertToInitialized(block, (byte) 0);                               
                                                } catch (Exception ex){
                                                    ex.printStackTrace();
                                                } finally {       
                                                    program.endTransaction(transactionID, true);                                                    
                                                } 
                                            }
                                            break;
                                        }
                                    }
                                    if (!isInSpace){
                                        handleError(isRunning, e);
                                        return false;
                                    }
                                }      
                            } else {
                                // perhaps we've got the memory change conflict
                                handleError(isRunning, e);
                                return false;
                            }
                        } finally {
                            program.endTransaction(transactionSB, true);
                        }
                    } else {
                        isEnoughSpace = true;
                    }
                }
                // Get bytes from emulator and write them to Ghidra program memory
                int transactionUM = program.startTransaction("UpdateMem");
                byte [] bytesToWrite = emuHelper.readMemory(start, len);
                try {
                    program.getMemory().setBytes(start, bytesToWrite);                        
                } catch (MemoryAccessException e1) {							
                    e1.printStackTrace();
                    handleError(isRunning, e1);
                    return false;
                } finally {
                    program.endTransaction(transactionUM, true);                
                } 

                // update ram in gui (not stack)
                Data data = program.getListing().getDataAt(start);
                if (!program.getMemory().getBlock(stackName).contains(start) && 
                data != null && data.isPointer()){
                        addressesToUpdate.put(start, len);
                    if (!isRunning){
                        // Update bytes if not running but stepping in the disassm listing
                        // Only applicable to pointers because data bytes 
                        // don't need to be updated (already)
                        updatePtrUnstable(start);                            	
                    }           
                }
            }
        }
        return true;
    }

    public void handleError(boolean isRunning, Exception e) {
        String errMsg = e.getMessage();
        if (isRunning) {
            if (!sw.isCancelled()){
                sw.publishWrap(errMsg);
            }
        } else {
            plugin.console.addMessage(originator, errMsg);
        }   
    }
    
    public void setEmuStackBytes() {
        byte[] dest = new byte[stackSize];
        try {
            program.getMemory().getBytes(stackStart, dest);
        } catch (MemoryAccessException e) {            
            e.printStackTrace();
        }
        emuHelper.writeMemory(stackStart, dest);
    }

    public void setEmuRegisters() {    	
        int counter = 0;
        for (String reg: RegisterProvider.regList) {
            try {
                emuHelper.writeRegister(reg, RegisterProvider.regsVals.get(counter).value);
                counter++;
            } catch (Exception ex) { }
        }
    }

    public void setEmuMemory() {      
        try {
            for (var line: GhidraEmuPopup.bytesToPatch) {
                emuHelper.writeMemory(line.start, line.bytes);
                userBytes.put(line.start, line.bytes.length);
            }	        
        } catch (Exception ex) {};
        GhidraEmuPopup.bytesToPatch.clear();
    }

    public boolean belongsToMem(long value){
        Address address = getAddressfromLong(value);
        for (MemoryBlock block : program.getMemory().getBlocks()){
            if (block.contains(address)) {
                return true;
            }
        }
        return false;
    }

    public boolean addrBelongsToMem(Address address){        
        for (MemoryBlock block : program.getMemory().getBlocks()){
            if (block.contains(address)) {
                return true;
            }
        }
        return false;
    }

    public void makeStep() {    	
        Address currentAddress = emuHelper.getExecutionAddress();
        Instruction currentInstruction = program.getListing().getInstructionAt(currentAddress);
        if (currentInstruction == null) {            
            message = badInsn;
            stopEmulationLight(null, false);
            return;
        }        
        GhidraEmuPopup.setColor(currentAddress, Color.getHSBColor(247, 224, 98));       
        
        // delayed branch painting
        if (hasBranchDelaySlot){
            Instruction nextInsn = getNextIfDelaySlot(currentInstruction);
            if (nextInsn != null){
                Address execBefore = nextInsn.getAddress();
                addTracedIfNotLast(execBefore);
                GhidraEmuPopup.setColor(execBefore, Color.getHSBColor(247, 224, 98));
            }
        }
        
        boolean success = false;
        try {
            success = emuHelper.step(monitor);
        } catch (Exception e) {            
            message = e.getMessage();
            stopEmulationLight(null, false);
            return;
        }    
        // Perhaps emulator faced with uninitialized memory during stepping
        if (emuHelper == null) {            
            return;
        }        
        
        Address executionAddress = emuHelper.getExecutionAddress();
        readEmuRegisters();
        if (!readMemFromEmu(false)){
            message = sthWrong;
            stopEmulationLight(executionAddress, false);
            return;
        }    
        
        if (!success) {
            message = emuHelper.getLastError();              
            stopEmulationLight(executionAddress, false);
            return;
        }

        addTracedIfNotLast(executionAddress);         
        GhidraEmuPopup.setColor(executionAddress, Color.orange);
        
        if (!belongsToMem(emuHelper.readRegister(emuHelper.getPCRegister()).longValue())) {
            message = unknowPC;
            stopEmulationLight(null, false);
            return;
        }

        try {
            ProgramLocation location = new ProgramLocation(program, executionAddress);
            lpanel.scrollTo(location);
        } 
        catch (Exception ex) {}
        processBreakpoint(executionAddress, false);
    }

    public void Run() {
        endLocation = null;
        message = null;
        Instruction currentInstruction = program.getListing().getInstructionAt(emuHelper.getExecutionAddress());
        if (currentInstruction == null) {            
            message = badInsn;
            stopEmulationLight(null, true);            
            return;
        }
        boolean success = false;
        try {
            success = emuHelper.run(monitor);
        } catch (Exception e) {            
            message = e.getMessage();
            stopEmulationLight(null, true);            
            return;
        }
        // Perhaps emulator faced with uninitialized memory during running
        if (emuHelper == null) {            
            return;
        }  
        
        Address executionAddress = emuHelper.getExecutionAddress();
        readEmuRegisters();
        if (!readMemFromEmu(true)){
            message = sthWrong;
            stopEmulationLight(executionAddress, true);
            return;
        }
        if (!success) {           
            message = emuHelper.getLastError();
            stopEmulationLight(executionAddress, true);          
            return;
        }
        if (!belongsToMem(emuHelper.readRegister(emuHelper.getPCRegister()).longValue())) {
            message = unknowPC;
            stopEmulationLight(null, true);
            return;
        }        
        if (!sw.isCancelled()){
            addTracedIfNotLast(executionAddress);            
            sw.publishWrap(null);
        }
        else {
            return;
        }        

        if (processBreakpoint(executionAddress, true)) {
            Run();
        } else {        
            if (emuHelper != null) {		        
                endLocation = new ProgramLocation(program, executionAddress);	       
            }
        }        
    }

    public boolean processBreakpoint(Address addr, boolean isRunning){
        if (stopEmu != null && addr.equals(stopEmu)) {  
            message = successMsg;
            stopEmulationLight(addr, isRunning);          
            return false;
        }
        if (stepOverToAddr != null && addr.equals(stepOverToAddr)){
            emuHelper.clearBreakpoint(stepOverToAddr);
            stepOverToAddr = null;
            return false;
        }

        for (ExternalFunction func: implementedFuncsPtrs){
            if (addr.equals(func.funcPtr)) {
                if (func.function.getName().equals("exit")){ 
                    message = successMsg;
                    stopEmulationLight(addr, isRunning);                   
                    return false;
                }
                if (!emulateKnownFunc(func, isRunning)){
                    return false;
                }
                ipBack(isRunning);
                return true;
            }
        }
        for (ExternalFunction func: unimplementedFuncsPtrs) {
            if (addr.equals(func.funcPtr)) {
                String msg = "Unimplemented function at address " + addr.toString() +  " : " + func.function.getName() + "!";
                if (isRunning){
                    if (!sw.isCancelled()){
                        sw.publishWrap(msg);
                    } else {
                        return false;
                    }                  
                } else {
                    plugin.console.addMessage(originator, msg);
                }               
                ipBack(isRunning);
                return true;
            }
        }        
        for (ExternalFunction func: computedCalls) {
            if (addr.equals(func.funcPtr)) {
                if (!isRunning){
                    GhidraEmuPopup.setColor(addr, Color.getHSBColor(247, 224, 98));
                }
                for (ExternalFunction unImplfunc: unimplementedFuncsPtrs) {
                    if (unImplfunc.function.equals(func.function)) {
                        String msg = "Call intercepted at address " +  unImplfunc.funcPtr.toString()  + " — "+ func.function.getName() + ".";
                        if (isRunning) {
                            if (!sw.isCancelled()){                            
                                sw.publishWrap(msg);
                            }
                            else {
                                return false;
                            }
                        } else {
                            plugin.console.addMessage(originator, msg);
                        }
                        setNextPC();
                        return true;
                    }
                }
                for (ExternalFunction Implfunc: implementedFuncsPtrs) {
                    if (Implfunc.function.equals(func.function)) {
                        if (!emulateKnownFunc(func, isRunning)){
                            return false;
                        }
                        setNextPC();
                        return true;
                    }
                }
            }
        }
        for (Address bp: breaks) {
            if (addr.equals(bp) && !isRunning) {
                GhidraEmuPopup.setColor(bp, Color.getHSBColor(247, 224, 98));
                return false;
            }
        }
        return false;
    }

    public void setNextPC(){    	
        emuHelper.writeRegister(RegisterProvider.PC, program.getListing().getInstructionAt(emuHelper.getExecutionAddress()).getNext().getAddress().getAddressableWordOffset());
        RegisterProvider.setRegister(RegisterProvider.PC, emuHelper.readRegister(RegisterProvider.PC));
    }

    public void stepOver(){
        // 1. set a hidden breakpoint to the next instruction (next-next if delayed branch slot)
        // 2. run (it will stop at bp)
        // 3. clear breakpoint
        
        Instruction currentInstruction = program.getListing().getInstructionAt(emuHelper.getExecutionAddress());        
        stepOverToAddr = currentInstruction.getNext().getAddress();
        if (hasBranchDelaySlot){
            Instruction nextInsn = getNextIfDelaySlot(currentInstruction);
            if (nextInsn != null) {
                if (!currentInstruction.getMnemonicString().contains("call")) {
                    makeStep();
                    return;
                } else {
                    stepOverToAddr = currentInstruction.getNext().getNext().getAddress();
                }
            }
        }
        emuHelper.setBreakpoint(stepOverToAddr);
        sw = new EmuRun();
        sw.execute();      
    }
    
    public void jumpOver() {    	
        Address badPlace = emuHelper.getExecutionAddress();
        GhidraEmuPopup.unsetColor(badPlace);
        setNextPC();
        Address newPC = emuHelper.getExecutionAddress();
        GhidraEmuPopup.setColor(newPC, Color.orange);
        addTracedIfNotLast(newPC);
        if (traced.contains(badPlace)) {
            traced.remove(badPlace);
        }   
    }

    public void stopEmulationLight(Address executionAddress, boolean isRunning){  
        if (emuHelper != null) {
            emuHelper.dispose();
            emuHelper = null;
        }
        
        if (executionAddress != null && belongsToMem(executionAddress.getAddressableWordOffset())) {
            endLocation = new ProgramLocation(program, executionAddress);
        }
        else {
            endLocation = new ProgramLocation(program, traced.get(traced.size()-1));
            if (!belongsToMem(endLocation.getAddress().getAddressableWordOffset())) {            
                endLocation = new ProgramLocation(program, traced.get(traced.size()-2));
            }
        }
        if (!isRunning) {
            try {
                GhidraEmuPopup.setColor(endLocation.getAddress(), Color.orange); 
                lpanel.scrollTo(endLocation);
                JOptionPane.showMessageDialog(null, message);    
            }
            catch (Exception ex) {};
        }        
        isStateClear = false;
    }

    public void resetState() {
        try {
            emuHelper.dispose();           
        } 
        catch (Exception ex) {}
        emuHelper = null;
        
        //Registers zeroed
        for (String reg: RegisterProvider.regList) {
            try {
                RegisterProvider.setRegister(reg, BigInteger.valueOf(0), false);
            } catch (Exception ex) {}
        }         
        RegisterProvider.setRegister(RegisterProvider.PC, BigInteger.valueOf(0));
        
        //Stack zeroed
        if (stackPointer != null) {
            int transactionID = -1;
            try {
                transactionID = program.startTransaction("UpdateStack");
                program.getMemory().setBytes(stackStart, new byte[stackSize]);
                GhidraEmuPlugin.stackProvider.contextChanged();
            } catch (Exception e) {
                e.printStackTrace();
            }  finally {       
                program.endTransaction(transactionID, true);
            } 
        }
        //Zero fields
        if (GhidraEmuPopup.start_address != null) {
            GhidraEmuPopup.unsetColor(GhidraEmuPopup.start_address);
            GhidraEmuPopup.start_address = null;
        }
        if (GhidraEmuPopup.stop_address != null) {
            GhidraEmuPopup.unsetColor(GhidraEmuPopup.stop_address);
            GhidraEmuPopup.stop_address = null;
        }
        startTF.setText("");
        stopTF.setText("");
        stopEmu = null;
        HashSet<Address> uniqueTraced = new HashSet<Address>(traced);
        for (Address colorAddress: uniqueTraced) {
            GhidraEmuPopup.unsetColor(colorAddress);
        }
        traced.clear();
        uniqueTraced.clear();
        for (Address bp: breaks) {
            GhidraEmuPopup.unsetColor(bp);
        }
        RegisterProvider.returnReg = null;
        breaks.clear();
        BreakpointProvider.breakModel.setRowCount(0);
        BreakpointProvider.breakTable.repaint();        
        message = null;
        if (endLocation != null){
            GhidraEmuPopup.unsetColor(endLocation.getAddress()); 
        }
        endLocation = null;       
        plugin.console.clearMessages();
        
        // restore origBytes changed by emulator, we've saved them
        // unfortunately FileBytes.getOriginalBytes can't provide original bytes
        // in some cases and returns zeros (e.g., with pointers)
        for (Address startAddess : origBytes.keySet()) {
            byte [] originalBytesForSet = origBytes.get(startAddess);
            int transactionID = -1;
            try {
                transactionID = program.startTransaction("RestoreMem");
                program.getMemory().setBytes(startAddess, originalBytesForSet);
            } catch (MemoryAccessException e) {			
                e.printStackTrace();
            } finally {       
                program.endTransaction(transactionID, true);
                Data data = program.getListing().getDataAt(startAddess);
                if (data != null && data.isPointer()){
                    updatePtrUnstable(startAddess);
                }
            } 
        }

        // As for bytes changed by users, we will assume that they're 
        // responsible for their own changes
        // getOriginalBytes#FileBytes is propriate Ghidra API for some cases but, e.g. if 
        // we're dealing with addresses that contain bytes, which are pointers,
        // getOriginalBytes#FileBytes won't help us and will return zero-bytes that will break the user's project

        // You can uncomment at your own risk
        /*
        for (FileBytes fileBytes : binBytes) {   
            for (Address startAddess : userBytes.keySet()) {
                int transactionID = -1;
                try {
                    int len = userBytes.get(startAddess);
                    byte[] origFileBytes = new byte[len];
                    fileBytes.getOriginalBytes(startAddess.getAddressableWordOffset() - program.getImageBase().getAddressableWordOffset(), origBytes, 0, len);   
                                        
                    transactionID = program.startTransaction("RestoreProgramBytesChnagedByUser");
                    program.getMemory().setBytes(startAddess, origFileBytes);                    
                } catch (MemoryAccessException | IOException e) {			
                    e.printStackTrace();
                } finally {       
                    program.endTransaction(transactionID, true);
                } 
            }
        } 
        userBytes.clear();
        */

        // bytes restored, can clear
        addressesToUpdate.clear();
        origBytes.clear();
        sw = null;
        isStateClear = true;
        panel.revalidate();
        panel.repaint();
    }
    
    public void getExternalAddresses() {
        implementedFuncsPtrs = new ArrayList <ExternalFunction> ();
        unimplementedFuncsPtrs = new ArrayList <ExternalFunction> ();
        computedCalls = new ArrayList <ExternalFunction>();
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
                                implementedFuncsPtrs.add(new ExternalFunction(ptrToFunc, f));
                            } else {
                                unimplementedFuncsPtrs.add(new ExternalFunction(ptrToFunc, f));
                            }
                        } else if (refType == RefType.COMPUTED_CALL) {  
                            computedCalls.add(new ExternalFunction(ptrToFunc, f));
                        }
                    }
                } else {
                    if (thunkAddrs.length == 1) {
                        if (knownFuncs.contains(f.getName())) {
                            implementedFuncsPtrs.add(new ExternalFunction(thunkAddrs[0], f));
                        } else {
                            unimplementedFuncsPtrs.add(new ExternalFunction(thunkAddrs[0], f));
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

    public void updatePtrUnstable(Address address) {
        int transactionID = -1;
        try {
            transactionID = program.startTransaction("UpdatePtr"); 
            DataUtilities.createData(program, address, new ByteDataType(), program.getDefaultPointerSize(), false,
                DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);    
            DataUtilities.createData(program, address, new PointerDataType(), program.getDefaultPointerSize(), false,
                DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
        } catch (CodeUnitInsertionException e) {
            e.printStackTrace();
        } finally {
            program.endTransaction(transactionID, true);
        }
    }

    public void ipBack(boolean isRunning) {
        try {
            if (processorName.equals("AARCH64")) {
                emuHelper.writeRegister(RegisterProvider.PC, emuHelper.readRegister("x30"));
            } else if (processorName.toLowerCase().contains("mips")) {
                emuHelper.writeRegister(RegisterProvider.PC, emuHelper.readRegister("ra"));
            } else if (RegisterProvider.regList.contains("LR")) {
                emuHelper.writeRegister(RegisterProvider.PC, emuHelper.readRegister("LR"));
            } else if (RegisterProvider.regList.contains("lr")) {
                emuHelper.writeRegister(RegisterProvider.PC, emuHelper.readRegister("lr"));
            } else if (processorName.toLowerCase().contains("sparc")) {
                Address callAddr = getAddressfromLong(emuHelper.readRegister("o7").longValue());
                Long nextAddr = program.getListing().getInstructionAfter(callAddr).getAddress().getAddressableWordOffset();              
                emuHelper.writeRegister(RegisterProvider.PC, nextAddr);
            } else if (RegisterProvider.returnReg != null) {
                emuHelper.writeRegister(RegisterProvider.PC, emuHelper.readRegister(RegisterProvider.returnReg));
            } else {            	
                emuHelper.writeRegister(RegisterProvider.PC, emuHelper.readStackValue(0, program.getDefaultPointerSize(), false));
            }
            BigInteger value = emuHelper.readRegister(RegisterProvider.PC);
            Address currentAddress = getAddressfromLong(value.longValue());
            RegisterProvider.setRegister(RegisterProvider.PC, value);

            if (!isRunning) {                
                addTracedIfNotLast(currentAddress);
                GhidraEmuPopup.setColor(currentAddress, Color.orange);
                ProgramLocation location = new ProgramLocation(program, currentAddress);
                lpanel.scrollTo(location);
            }
            else {
                if (!sw.isCancelled()){
                    addTracedIfNotLast(currentAddress);
                    sw.publishWrap(null);
                }   
                else {
                    return;
                }
            }
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
                int transactionID = -1;
                try {
                    transactionID = program.startTransaction("Mapping Heap");
                    MemoryBlock newBlock = program.getMemory().createInitializedBlock("Heap", heapAddr, MALLOC_REGION_SIZE, (byte) 0,
                        TaskMonitor.DUMMY, false);
                    newBlock.setPermissions(true, true, true);
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    program.endTransaction(transactionID, true);
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
    
    public Address getAddressfromInt(int offset) {
        return program.getAddressFactory().getAddress(Integer.toHexString(offset));        
    }
    
    public Address getAddressfromLong(long offset) {
        // should be only code address space (PC)
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset, true);
    }

    public Address getAddressFromString(String addrString) {        
        return program.getAddressFactory().getAddress(addrString);
    }
    
    public boolean emulateKnownFunc(ExternalFunction func, boolean isRunning) {
        BigInteger operandValue = emuHelper.readRegister(RegisterProvider.conventionRegs.get(0));
        Address operandValueAddr = getAddressFromString(operandValue.toString(16));
        Function emuFunc = func.function;
        switch(emuFunc.getName()) {
            case "malloc": 
                int size = operandValue.intValue();
                Address memAddr = null;
                try {
                    memAddr = mallocMgr.malloc(size);
                } catch (InsufficientBytesException e) {                
                    e.printStackTrace();
                }
                Register returnReg = emuFunc.getReturn().getRegister();         
                emuHelper.writeRegister(returnReg, memAddr.getAddressableWordOffset());
                RegisterProvider.setRegister(returnReg.getName(), memAddr);
                break;
            case "free":
                mallocMgr.free(operandValueAddr);
                break;
            case "puts":
                String msg = "puts(" + emuHelper.readNullTerminatedString(operandValueAddr, 0x1000) + ")";               
                if (isRunning) {
                    if (!sw.isCancelled()){
                        sw.publishWrap(msg);
                    }
                } else {
                    plugin.console.addMessage(originator, msg);
                }
                break;
            case "strlen":
                int len = 0;
                while (emuHelper.readMemoryByte(operandValueAddr) != 0) {
                    ++len;
                    operandValueAddr = operandValueAddr.next();
                }
                if (emuHelper == null) {
                    // error during emulate read operation
                    return false;
                } 
                Register retReg = emuFunc.getReturn().getRegister();                
                emuHelper.writeRegister(retReg, len);
                RegisterProvider.setRegister(retReg.getName(), BigInteger.valueOf(len));
                break;           
        }
        return true;
    }
}
