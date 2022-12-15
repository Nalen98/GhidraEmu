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
import ghidra.app.plugin.core.function.editor.FunctionEditorModel;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.framework.plugintool.PluginTool;
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
    public static final String sthWrong = "Check out your emulation options, something wrong!";
    public static final int MALLOC_REGION_SIZE = 0x1000;       
    public static EmulatorHelper emuHelper;      
    public static ArrayList <Address> breaks;
    public static HashMap<Address, Integer> addressesToUpdate;
    public static HashMap<Address, Integer> userBytes;
    public static HashMap<Address, byte[]> origBytes;
    public static JTextField startTF;
    public static JTextField stopTF;       
    public static Program program;   
    public PluginTool tool;
    public GhidraEmuPlugin plugin;
    public Border classicBorder;    
    public Address stopEmu;
    public ConsoleTaskMonitor monitor;
    public ArrayList <Address> traced;    
    public MallocManager mallocMgr;    
    public VarnodeContext context;
    public ListingPanel lpanel;
    public List<FileBytes> binBytes;    
    public int stackSize;
    public Address stackPointer;
    public Address stackStart;
    public EmuRun sw;
    public ProgramLocation endLocation;
    public String message;
    public String processorName;
    public String stackName;
    private ArrayList <ExternalFunction> implementedFuncsPtrs;
    private ArrayList <ExternalFunction> unimplementedFuncsPtrs;
    private ArrayList <ExternalFunction> computedCalls;
    private ArrayList <String> knownFuncs;
    private boolean hasHeap;
    private JPanel panel;

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
            ArrayList <Address> toPaint = new ArrayList<Address>(traced);
            for (Address addr : toPaint){
                if (!painted.contains(addr)) {
                    if (isCancelled()) {
                        return;
                    }
                    GhidraEmuPopup.setColor(addr, Color.getHSBColor(247, 224, 98));
                }               
            }   
            painted.addAll(toPaint);        	         
        }
    
        @Override
        protected void done() {        	                              
            if (endLocation != null){                            
            	try {
	                lpanel.scrollTo(endLocation);
	                GhidraEmuPopup.setColor(endLocation.getAddress(), Color.getHSBColor(247, 224, 98)); 
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
                if (endLocation != null){
                    GhidraEmuPopup.setColor(endLocation.getAddress(), Color.orange); 
                }
                JOptionPane.showMessageDialog(null, message);
            }                         
        }   
        
        public void publishWrap(String msg) {
            publish(msg);
        }
    }
    
    public GhidraEmuProvider(GhidraEmuPlugin ghidraEmuPlugin, String pluginName) {
        super(ghidraEmuPlugin.getTool(), pluginName, pluginName);
        this.tool = ghidraEmuPlugin.getTool();
        this.plugin = ghidraEmuPlugin;
        setIcon(ResourceManager.loadImage("images/ico.png"));
        setProgram(program);
        setWindowMenuGroup("GhidraEmu");
        traced = new ArrayList <Address> ();
        breaks = new ArrayList <Address> ();
        addressesToUpdate = new HashMap<Address, Integer>();
        userBytes = new HashMap<Address, Integer>();
        origBytes = new HashMap<Address, byte[]>();        
        knownFuncs = new ArrayList <String> (Arrays.asList("malloc", "free", "puts", "strlen", "exit"));
        lpanel = plugin.codeViewer.getListingPanel();    	
        emuHelper = null;
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
                stepEmulation();
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
                    .addGap(32)
                    .addComponent(runBtn, GroupLayout.DEFAULT_SIZE, 96, Short.MAX_VALUE)
                    .addGap(32)
                    .addComponent(stepBtn, GroupLayout.DEFAULT_SIZE, 96, Short.MAX_VALUE)
                    .addGap(32)
                    .addComponent(resetBtn, GroupLayout.DEFAULT_SIZE, 96, Short.MAX_VALUE)
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
            stopEmu = program.getAddressFactory().getAddress(stopTF.getText());
        } else {
            // non stop emulation
            stopEmu = null;
        }
        return true;
    }

    
    public boolean initEmulation() {
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
        RegisterProvider.setRegister(RegisterProvider.PC, program.getAddressFactory().getAddress(startTF.getText()));
        try {
            emuHelper = new EmulatorHelper(program);
            emuHelper.enableMemoryWriteTracking(true);
            monitor = new ConsoleTaskMonitor() {
                @Override
                public void checkCanceled() throws CancelledException {
                    Address address = emuHelper.getExecutionAddress();                    
                    if (sw == null){
                        // run never started
                        if (!traced.contains(address)){
                            traced.add(address);
                        }
                    } else {
                        if (!sw.isCancelled() && !sw.isDone()){
                            // just running 
                            if (!traced.contains(address)){
                                traced.add(address);
                                sw.publishWrap(null);
                            }
                        }                       
                    }
                }
            };
            context = new VarnodeContext(program, new ProgramContextImpl(program.getLanguage()), new ProgramContextImpl(program.getLanguage()));
            message = null;
            endLocation = null;     
            
            // get processor name
            processorName = program.getLanguage().getProcessor().toString();
            
            for (MemoryBlock block : program.getMemory().getBlocks()) {
            	String blockName = block.getName();
            	if (blockName.toLowerCase().contains("stack")) {
                    stackName = blockName;
                    break;
                }                
            }
            
            stackStart = program.getMemory().getBlock(stackName).getStart();          
            stackSize = (int)program.getMemory().getBlock(stackName).getSize();
            long stackPointerAsLong = stackStart.getOffset() + stackSize/2;
            if (processorName.equalsIgnoreCase("V850")){
                stackPointerAsLong = 0xFFFFFFFF;					
            }
            stackPointer = getAddressfromLong(stackPointerAsLong);            
            
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
                return;
            }
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
            if (start.getAddressSpace().getName().equalsIgnoreCase("ram")) { 
                boolean isEnoughSpace = false;
                while (!isEnoughSpace){
                	int transactionSB = -1;
                	int transactionUM = -1;
                    try {                    	
                        if (!program.getMemory().getBlock(stackName).contains(start) && !origBytes.containsKey(start)){
                            byte [] beforeChange = new byte[len];
                            transactionSB = program.startTransaction("SaveOrigBytes");                            
                            program.getMemory().getBytes(start, beforeChange);
                            program.endTransaction(transactionSB, true);
                            origBytes.put(start, beforeChange);
                            transactionSB = 0;
                        }

                        transactionUM = program.startTransaction("UpdateMem");
                        program.getMemory().setBytes(start, emuHelper.readMemory(start, len));
                        program.endTransaction(transactionUM, true);
                        transactionUM = 0;
                        isEnoughSpace = true;  

                        // update ram in gui (not stack)
                        if (!program.getMemory().getBlock(stackName).contains(start) && 
                            program.getListing().getDataAt(start).isPointer()){
                                addressesToUpdate.put(start, len);
                            if (!isRunning){
                                // Update bytes if not running but stepping in the disassm listing
                                // Only applicable to pointers because data bytes 
                                // don't need to be updated (already)
                                updatePtrUnstable(start);                            	
                            }           
                        }                               
                    } catch (ghidra.pcode.error.LowlevelError | ghidra.program.model.mem.MemoryAccessException e ) {  
                        e.printStackTrace();
                        if (transactionSB != -1 && transactionSB != 0) {
                    		program.endTransaction(transactionSB, true);
                    	}
                    	if (transactionUM != -1 && transactionUM != 0) {
                    		program.endTransaction(transactionUM, true);
                    	}
                        if (e.getMessage().contains("Unable to read bytes at ram")){
                        	// If the error has something to do with the fact that not enough stack is allocated, 
                        	// it is necessary to recognize and fix it. Otherwise, we are dealing with uninitialized 
                        	// memory and it must be corrected by the user himself.
                      
                        	String conflictAddressStr = e.getMessage().substring(e.getMessage().indexOf("ram:") + 4);
                        	Address conflictAddress = program.getAddressFactory().getAddress(conflictAddressStr);   
                        	Address deadLine = stackStart.subtract(0x1000);
                        	int cmp1 = conflictAddress.compareTo(stackStart);
                        	int cmp2 = conflictAddress.compareTo(deadLine);
                        	if  (cmp1 <= 0 && cmp2 >= 0) {
                        		// set more space for stack
                                MemoryBlock expandBlock = program.getMemory().getBlock(stackName);
                                Memory memory = program.getMemory();
                                MemoryBlock newBlock;
                                int transactionID = -1;
                                try {
                                    stackSize = stackSize + 0x1000;                            
                                    stackStart = getAddressfromLong(stackStart.getOffset() - 0x1000);
                                    transactionID= program.startTransaction("Mapping"); 
                                    newBlock = memory.createInitializedBlock(stackName, 
                                            stackStart, 0x1000, (byte) 0, TaskMonitor.DUMMY, false);
                                    memory.join(newBlock, expandBlock);
                                    program.endTransaction(transactionID, true);
                                    transactionID = 0;                                
                                } catch (Exception ex) {		
                                	if (transactionID != -1 && transactionID != 0) {
                                		program.endTransaction(transactionID, true);
                                	}
                                    ex.printStackTrace();
                                    return false;
                                } 
                            } else {
                                // uninitialized memory
                                handleError(isRunning, e);
                                return false;
                            }      
                        } 
                        else {
                            // perhaps we've got the memory change conflict
                            handleError(isRunning, e);
                            return false;
                        }
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

    public static void setEmuMemory() {      
        try {
            for (var line: GhidraEmuPopup.bytesToPatch) {
                emuHelper.writeMemory(line.start, line.bytes);
                userBytes.put(line.start, line.bytes.length);
            }	        
        } catch (Exception ex) {};
        GhidraEmuPopup.bytesToPatch.clear();
    }

    public void makeStep() {    	
        Instruction currentInstruction = program.getListing().getInstructionAt(emuHelper.getExecutionAddress());
        if (currentInstruction == null) {
            JOptionPane.showMessageDialog(null, "Bad Instruction!");
            resetState();
            return;
        }
        boolean success = false;
        try {
            success = emuHelper.step(monitor);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(null, e.getStackTrace());
            resetState();
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
        
        traced.add(executionAddress);
        GhidraEmuPopup.setColor(executionAddress, Color.getHSBColor(247, 224, 98));
        
        if (emuHelper.readRegister(emuHelper.getPCRegister()) == BigInteger.valueOf(0)) {
            message = successMsg;
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
            JOptionPane.showMessageDialog(null, "Bad Instruction!");
            resetState();
            return;
        }
        boolean success = false;
        try {
            success = emuHelper.run(monitor);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(null, e.getStackTrace());
            resetState();
            return;
        }

        Address executionAddress = emuHelper.getExecutionAddress();
        readEmuRegisters();
        if (!readMemFromEmu(true)){
            message = sthWrong;
            stopEmulationLight(executionAddress, true);
            return;
        }       
        
        if (executionAddress.getOffset() == 0) {    
            message = successMsg;
            stopEmulationLight(null, true);
            return;
        }        
        if (!success) {           
            message =  emuHelper.getLastError();
            stopEmulationLight(executionAddress, true);          
            return;
        }

        if (emuHelper.readRegister(emuHelper.getPCRegister()) == BigInteger.valueOf(0)) {
            message = successMsg;
            stopEmulationLight(null, true);
            return;
        }
        
        if (!sw.isCancelled()){
            traced.add(executionAddress);
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

    public boolean processBreakpoint(Address addr, boolean isRunning) {
        if (stopEmu != null && addr.equals(stopEmu)) {  
            message = successMsg;
            stopEmulationLight(addr, isRunning);          
            return false;
        }
        for (ExternalFunction func: implementedFuncsPtrs) {
            if (addr.equals(func.funcPtr)) {
            if (func.function.getName().equals("exit")){ 
                message = successMsg;
                    stopEmulationLight(addr, isRunning);                   
                    return false;
            }             
                emulateKnownFunc(func, isRunning);
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
                        emuHelper.writeRegister(RegisterProvider.PC, program.getListing().getInstructionAt(emuHelper.getExecutionAddress()).getNext().getAddress().getOffset());
                        RegisterProvider.setRegister(RegisterProvider.PC, emuHelper.readRegister(RegisterProvider.PC));
                        return true;
                    }
                }
                for (ExternalFunction Implfunc: implementedFuncsPtrs) {
                    if (Implfunc.function.equals(func.function)) {
                        emulateKnownFunc(func, isRunning);
                        emuHelper.writeRegister(RegisterProvider.PC, program.getListing().getInstructionAt(emuHelper.getExecutionAddress()).getNext().getAddress().getOffset());
                        RegisterProvider.setRegister(RegisterProvider.PC, emuHelper.readRegister(RegisterProvider.PC));
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

    public void stopEmulationLight(Address executionAddress, boolean isRunning){  
    	if (emuHelper != null) {
    		emuHelper.dispose();
    		emuHelper = null;
    	}
        
        if (executionAddress!=null) {
            endLocation = new ProgramLocation(program, executionAddress);
        }
        else {
            endLocation = new ProgramLocation(program, traced.get(traced.size()-2));
        }
        if (!isRunning) {
        	try {
                GhidraEmuPopup.setColor(endLocation.getAddress(), Color.orange); 
                lpanel.scrollTo(endLocation);
                JOptionPane.showMessageDialog(null, message);    
        	}
        	catch (Exception ex) {};
        }
    }

    public void resetState() {  
        //Registers zeroed
        for (String reg: RegisterProvider.regList) {
            try {
                RegisterProvider.setRegister(reg, BigInteger.valueOf(0), false);
            } catch (Exception ex) {}
        }
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
    
        for (Address colorAddress: traced) {
            GhidraEmuPopup.unsetColor(colorAddress);
        }
        traced.clear();
        for (Address bp: breaks) {
            GhidraEmuPopup.unsetColor(bp);
        }
        RegisterProvider.returnReg = null;
        breaks.clear();
        BreakpointProvider.breakModel.setRowCount(0);
        BreakpointProvider.breakTable.repaint();
        try {
            emuHelper.dispose();
        } 
        catch (Exception ex) {}
        emuHelper = null;        
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
                updatePtrUnstable(startAddess);
            } catch (MemoryAccessException e) {			
                e.printStackTrace();
            } finally {       
                program.endTransaction(transactionID, true);
            } 
        }

        // As for the bytes changed by the users, we will assume that they theirself is 
        // responsible for their own changes
        // getOriginalBytes#FileBytes is the nice Ghidra API for some cases but, e.g. if 
        // we're dealing with addresses that contain bytes, which are the pointers
        // getOriginalBytes#FileBytes won't help us and returns zero-bytes which will break the user's project

        // You can uncomment at your own risk
        /*
        for (FileBytes fileBytes : binBytes) {   
            for (Address startAddess : userBytes.keySet()) {
                int transactionID = -1;
                try {
                    int len = userBytes.get(startAddess);
                    byte[] origFileBytes = new byte[len];
                    fileBytes.getOriginalBytes(startAddess.getOffset() - program.getImageBase().getOffset(), origBytes, 0, len);   
                                        
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
            if (program.getLanguage().getProcessor().toString().equals("AARCH64")) {
                emuHelper.writeRegister(RegisterProvider.PC, emuHelper.readRegister("x30"));
            } else if (program.getLanguage().getProcessor().toString().toLowerCase().contains("mips")) {
                emuHelper.writeRegister(RegisterProvider.PC, emuHelper.readRegister("ra"));
            } else if (RegisterProvider.regList.contains("LR")) {
                emuHelper.writeRegister(RegisterProvider.PC, emuHelper.readRegister("LR"));
            } else if (RegisterProvider.regList.contains("lr")) {
                emuHelper.writeRegister(RegisterProvider.PC, emuHelper.readRegister("lr"));
            } else if (RegisterProvider.returnReg != null) {
                emuHelper.writeRegister(RegisterProvider.PC, emuHelper.readRegister(RegisterProvider.returnReg));
            } else {
                emuHelper.writeRegister(RegisterProvider.PC, emuHelper.readStackValue(0, 8, false));
            }
            BigInteger value = emuHelper.readRegister(RegisterProvider.PC);
            Address currentAddress = getAddressfromLong(value.longValue());
            RegisterProvider.setRegister(RegisterProvider.PC, value);

            if (!isRunning) {
                traced.add(currentAddress);
                GhidraEmuPopup.setColor(currentAddress, Color.getHSBColor(247, 224, 98));
                ProgramLocation location = new ProgramLocation(program, currentAddress);
                lpanel.scrollTo(location);
            }
            else {
                if (!sw.isCancelled()){
                    traced.add(currentAddress);
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
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }
    
    public void emulateKnownFunc(ExternalFunction func, boolean isRunning) {
        BigInteger operandValue = emuHelper.readRegister(RegisterProvider.conventionRegs.get(0));
        Address operandValueAddr = program.getAddressFactory().getAddress(operandValue.toString(16));
        switch(func.function.getName()) {
            case "malloc": 
                int size = operandValue.intValue();
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
                FunctionEditorModel fModel = new FunctionEditorModel(null, func.function);
                Register retReg = fModel.getReturnStorage().getRegister();
                emuHelper.writeRegister(retReg, len);
                RegisterProvider.setRegister(retReg.getName(), BigInteger.valueOf(len));
                break;           
        }
    }
}
