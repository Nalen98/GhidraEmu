/* ###
* IP: GHIDRA
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package byteviewerEmu;

import java.awt.event.*;
import java.math.BigInteger;
import java.util.List;
import java.util.Set;

import javax.swing.*;

import docking.ActionContext;
import docking.action.*;
import docking.widgets.fieldpanel.support.ViewerPosition;
import ghidra.app.events.*;
import ghidra.app.nav.*;
import ghidra.app.plugin.core.byteviewer.ByteViewerPlugin;
import ghidra.app.plugin.core.format.*;
import ghidra.app.services.ClipboardService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.framework.model.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidraemu.GhidraEmuPlugin;
import resources.ResourceManager;

public class ProgramByteViewerComponentProviderEmu extends ByteViewerComponentProviderEmu
        implements DomainObjectListener, Navigatable {

    private ImageIcon navigatableIcon;

    protected DecoratorPanel decorationComponent;
    private WeakSet<NavigatableRemovalListener> navigationListeners =
        WeakDataStructureFactory.createSingleThreadAccessWeakSet();

    private CloneByteViewerAction cloneByteViewerAction;

    protected Program program;
    protected ProgramSelection currentSelection;
    protected ProgramSelection currentHighlight;
    protected ProgramLocation currentLocation;
    private ClipboardService clipboardService;
    private ByteViewerClipboardProvider clipboardProvider;
    private final boolean isConnected;
    private boolean disposed;
    public static Address stackStart;
    public static String stackName;

    public ProgramByteViewerComponentProviderEmu(PluginTool tool, ByteViewerPluginEmu byteViewerPlugin,
            boolean isConnected) {
        super(tool, byteViewerPlugin, "Emu Stack", ByteViewerActionContext.class);
        setIcon(ResourceManager.loadImage("images/ico.png"));
        this.isConnected = isConnected;
        if (!isConnected) {
            setTransient();
        }
        else {
            addToToolbar();
        }

        decorationComponent = new DecoratorPanel(panel, isConnected);
        clipboardProvider = new ByteViewerClipboardProvider(this, tool);
        addToTool();

        createProgramActions();
        updateTitle();
        registerNavigatable();
    }

    public void createProgramActions() {
        cloneByteViewerAction = new CloneByteViewerAction();
        tool.addLocalAction(this, cloneByteViewerAction);
    }

    @Override
    public boolean isSnapshot() {
        // we are a snapshot when we are 'disconnected'
        return !isConnected();
    }

    @Override
    public JComponent getComponent() {
        return decorationComponent;
    }

    @Override
    public String getWindowGroup() {
        if (isConnected()) {
            return "";
        }
        return "disconnected";
    }

    @Override
    public void componentShown() {
        panel.refreshView();

        if (currentLocation != null) {
            if (program == null) {
                doSetProgram(currentLocation.getProgram());
            }

            setLocation(currentLocation);
        }
        if (currentSelection != null) {
            setSelection(currentSelection, false);
        }
    }

    @Override
    public ActionContext getActionContext(MouseEvent event) {
        return getByteViewerActionContext();
    }

    ByteViewerActionContext getByteViewerActionContext() {
        ByteBlockInfo info = panel.getCursorLocation();
        if (info == null) {
            return null;
        }
        return new ByteViewerActionContext(this);
    }

    @Override
    public void closeComponent() {
        // overridden to handle snapshots
        plugin.closeProvider(this);
    }

    @Override
    public void setSelection(ProgramSelection selection) {
        setSelection(selection, true);
    }

    @Override
    public ProgramSelection getSelection() {
        return currentSelection;
    }

    @Override
    public ProgramSelection getHighlight() {
        return currentHighlight;
    }

    @Override
    public String getTextSelection() {
        return getTextSelection();
    }

    private void setSelection(ProgramSelection selection, boolean notify) {
        currentSelection = selection;
        if (selection == null) {
            return;
        }

        if (!tool.isVisible(this)) {
            return;
        }

        ByteBlockSelection blockSelection = blockSet.getBlockSelection(selection);
        clipboardProvider.setSelection(currentSelection);

        panel.setViewerSelection(blockSelection);

        if (notify) {
            ProgramSelectionPluginEvent selectionEvent =
                blockSet.getPluginEvent(getName(), blockSelection);
            plugin.updateSelection(this, selectionEvent, program);
        }
        contextChanged();
    }

    @Override
    public boolean supportsHighlight() {
        return true;
    }

    @Override
    public void setHighlight(ProgramSelection newHighlight) {
        currentHighlight = newHighlight;
        if (newHighlight == null) {
            return;
        }

        if (!tool.isVisible(this)) {
            return;
        }

        ByteBlockSelection highlight = blockSet.getBlockSelection(currentHighlight);
        panel.setViewerHighlight(highlight);
        contextChanged();
        plugin.highlightChanged(this, newHighlight);

    }

    void enablePaste(boolean enabled) {
        clipboardProvider.setPasteEnabled(enabled);
    }

    public void doSetProgram(Program newProgram) {
        setOptionsAction.setEnabled(newProgram != null);
        cloneByteViewerAction.setEnabled(newProgram != null);

        if (program != null) {
            program.removeListener(this);
        }

        program = newProgram;

        clipboardProvider.setProgram(newProgram);
        for (ByteViewerComponent byteViewerComponent : viewMap.values()) {
            DataFormatModel dataModel = byteViewerComponent.getDataModel();
            if (dataModel instanceof ProgramDataFormatModel) {
                ((ProgramDataFormatModel) dataModel).setProgram(newProgram);
            }
        }

        if (newProgram != null) {
            newProgram.addListener(this);
        }
        setStack();

        setByteBlocks(null);
        updateTitle();
    }

    private void updateTitle() {
        String title =
            "GhidraEmu - StackView: " + (program == null ? "No Program" : program.getDomainFile().getName());
        if (!isConnected()) {
            title = "[" + title + "]";
        }

        setTitle(title);
    }

//==================================================================================================
// Navigatable interface methods */
//==================================================================================================

    public void setStack() {
        boolean hasStack = false;
        stackName = "Stack";
        try {
            AddressFactory addrFactory = program.getAddressFactory();
            String processorName = program.getLanguage().getProcessor().toString();
            Memory memory = program.getMemory();
            long stackOffset = ((program.getMinAddress().getAddressSpace().getMaxAddress().getOffset()>>> 5) - 0x7fff);
            Address temp = addrFactory.getAddress(Long.toHexString(stackOffset - 0x1000));
            if (processorName.equalsIgnoreCase("v850") || processorName.equalsIgnoreCase("sparc")){
                temp = addrFactory.getAddress(Long.toHexString(0xFFFFFFFF - 0x1FFF));
            }
            if (processorName.toLowerCase().contains("avr")){
                try {
                    Address sramEnd = memory.getBlock("sram").getEnd();
                    temp = sramEnd.add(0x1001);
                } catch (Exception ex) {};
            }
            if (processorName.equalsIgnoreCase("8051")){
                try {
                    // Should exist in any case
                	String ramName = "INTMEM";
                	for (MemoryBlock block : memory.getBlocks()) {
                		if (block.getStart().getAddressSpace().getName().equals(ramName)) {
                			if (!block.isInitialized()) {
                                initStack(memory, block);
                            }
                		}
                	}
                    stackStart = memory.getBlock("REG_BANK_1").getStart();
                    return;
                } catch (Exception ex) {};
            }

            stackStart = temp;
            for (MemoryBlock block : memory.getBlocks()) {
                String blockName = block.getName();
                if (blockName.toLowerCase().contains("stack")) {
                    if (!block.isInitialized()) {
                        initStack(memory, block);
                    }
                    stackName = blockName;
                    hasStack = true;
                    break;
                }
            }
            if (!hasStack) {
            	int transactionID = -1;
                try {
                	transactionID = program.startTransaction("Mapping");
                    MemoryBlock newBlock = memory.createInitializedBlock(stackName, stackStart, 0x2000, (byte) 0,
                        TaskMonitor.DUMMY, false);
                    newBlock.setPermissions(true, true, true);
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    program.endTransaction(transactionID, true);
                }
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public void initStack(Memory memory, MemoryBlock block){
        int transactionID = -1;
        try {
            transactionID = program.startTransaction("Init_stack_bytes");
            memory.convertToInitialized(block, (byte) 0);
        } catch (Exception ex){
            ex.printStackTrace();
        } finally {
            program.endTransaction(transactionID, true);
        }
    }

    @Override
    public ProgramLocation getLocation() {
        return currentLocation;
    }

    @Override
    public Program getProgram() {
        return program;
    }

    @Override
    public boolean goTo(Program gotoProgram, ProgramLocation location) {
        if (gotoProgram != this.program) {
            if (!isConnected()) {
                tool.setStatusInfo("Program location not applicable for this provider!");
                return false;
            }
            ProgramManager programManagerService = tool.getService(ProgramManager.class);
            if (programManagerService != null) {
                programManagerService.setCurrentProgram(gotoProgram);
            }
        }
        setLocation(location, false);
        return true;

    }

    @Override
    public LocationMemento getMemento() {
        ByteBlockInfo info = panel.getCursorLocation();
        int blockNumber = -1;
        BigInteger blockOffset = null;
        int column = 0;

        if (info != null) {
            blockNumber = getBlockNumber(info);
            blockOffset = info.getOffset();
            column = info.getColumn();
        }

        ViewerPosition vp = panel.getViewerPosition();
        return new ByteViewerLocationMemento(program, currentLocation, blockNumber, blockOffset,
            column, vp);
    }

    @Override
    public void setMemento(LocationMemento memento) {
        ByteViewerLocationMemento bvMemento = (ByteViewerLocationMemento) memento;

        int blockNumber = bvMemento.getBlockNum();
        BigInteger blockOffset = bvMemento.getBlockOffset();
        ViewerPosition vp = bvMemento.getViewerPosition();
        int column = bvMemento.getColumn();

        ByteBlock[] blocks = getByteBlocks();
        if (blocks != null && blockNumber>= 0 && blockNumber <blocks.length) {
            ByteViewerState view = new ByteViewerState(blockSet,
                new ByteBlockInfo(blocks[blockNumber], blockOffset, column), vp);
            panel.returnToView(view);
        }

    }

    @Override
    public boolean isConnected() {
        return isConnected;
    }

    @Override
    public boolean supportsMarkers() {
        return isConnected;
    }

    @Override
    public boolean isDisposed() {
        return disposed;
    }

    @Override
    public Icon getIcon() {
        if (isConnected()) {
            return super.getIcon();
        }

        if (navigatableIcon == null) {
            Icon primaryIcon = super.getIcon();
            navigatableIcon = NavigatableIconFactory.createSnapshotOverlayIcon(primaryIcon);
        }
        return navigatableIcon;
    }

    @Override
    public Icon getNavigatableIcon() {
        return getIcon();
    }

    @Override
    public boolean isVisible() {
        return tool.isVisible(this);
    }


//==================================================================================================
// End Navigatable interface methods */
//==================================================================================================

    public void setLocation(ProgramLocation location, boolean fireEvent) {
        currentLocation = location;
        if (location == null) {
            return;
        }

        if (!tool.isVisible(this)) {
            return;
        }

        clipboardProvider.setLocation(location);

        Address address = location.getByteAddress();
        if (!program.getMemory().contains(address)) {
            CodeUnit cu = program.getListing().getCodeUnitAfter(address);
            if (cu != null) {
                address = cu.getMinAddress();
            }
        }

        if (address == null) {
            return;
        }

        ByteBlockInfo byteBlockInfo = blockSet.getByteBlockInfo(address);
        if (byteBlockInfo == null) {
            return;
        }

        ByteBlock block = byteBlockInfo.getBlock();
        BigInteger blockOffset = byteBlockInfo.getOffset();

        int column = 0;
        if (location instanceof ByteViewerProgramLocation) {
            // the character offset only makes sense when coming from the byte viewer; other
            // location character offsets don't match the byte viewer's display
            column = location.getCharOffset();
        }

        panel.setCursorLocation(block, blockOffset, column);
        Address blockSetAddress = blockSet.getAddress(block, blockOffset);
        if (blockSetAddress == null) {
            return; // this can happen during an undo
        }

        currentLocation = getLocation(block, blockOffset, column);

        if (fireEvent && tool.isVisible(this)) {
            updateLocation(block, blockOffset, column, false);
            plugin.fireProgramLocationPluginEvent(this,
                blockSet.getPluginEvent(getName(), block, blockOffset, column));
        }
        else {
            contextChanged();
        }
    }

    ProgramLocation getLocation(ByteBlock block, BigInteger offset, int column) {
        Address address = blockSet.getAddress(block, offset);
        int characterOffset = column;
        ProgramLocation loc = new ByteViewerProgramLocation(program, address, characterOffset);
        return loc;
    }

    void setLocation(ProgramLocation location) {
        setLocation(location, false);
    }

    /**
    * Called when the memory in the current program changes, from the domain
    * object listener.
    */
    void memoryConfigurationChanged() {
        ProgramLocation location = currentLocation;
        ProgramSelection selection = currentSelection;
        // reuse byte block change manager so we don't lose track of what has
        // been edited

        ByteBlockChangeManager bbcm = null;
        if (blockSet != null) {
            bbcm = blockSet.getByteBlockChangeManager();
        }

        setByteBlocks(bbcm);

        if (!tool.isVisible(this)) {
            return;
        }

        setLocation(location, true);
        setSelection(selection, true);
    }

    void doHandleEvent(PluginEvent event) {
        if (event instanceof ProgramActivatedPluginEvent) {
            ProgramActivatedPluginEvent ev = (ProgramActivatedPluginEvent) event;
            Program newProgram = ev.getActiveProgram();
            if (program == null) {
                doSetProgram(newProgram);
                setLocation(null);
                setSelection(null, false);
            }
            return;
        }

        ByteBlock[] blocks = getByteBlocks();
        if (blocks == null) {
            return;
        }

        if (event instanceof ByteBlockChangePluginEvent) {
            blockSet.processByteBlockChangeEvent((ByteBlockChangePluginEvent) event);
        }
        else if (event instanceof ProgramLocationPluginEvent) {
            ProgramLocationPluginEvent ev = (ProgramLocationPluginEvent) event;
            processLocationEvent(ev);
        }
        else if (event instanceof ProgramSelectionPluginEvent) {
            ProgramSelectionPluginEvent ev = (ProgramSelectionPluginEvent) event;
            processSelectionEvent(ev);
        }
        else if (event instanceof ProgramHighlightPluginEvent) {
            processHighlightEvent((ProgramHighlightPluginEvent) event);
        }
    }

    private void processHighlightEvent(ProgramHighlightPluginEvent event) {
        ProgramSelection programSelection = event.getHighlight();
        setHighlight(programSelection);
    }

    private void processSelectionEvent(ProgramSelectionPluginEvent event) {
        ProgramSelection programSelection = event.getSelection();
        setSelection(programSelection);
    }

    private void processLocationEvent(ProgramLocationPluginEvent event) {
        //ProgramLocation loc = event.getLocation();
        //setLocation(loc);
        return;
    }

    public void notifyEdit(ByteEditInfo edit) {
        if (tool.isVisible(this)) {
            plugin.firePluginEvent(new ByteBlockChangePluginEvent(plugin.getName(), edit, program));
        }
    }

    ProgramLocation getCurrentLocation() {
        return currentLocation;
    }

    ProgramSelection getCurrentSelection() {
        return currentSelection;
    }

    /**
    * Gets the text of the current {@link ProgramSelection}
    * @return the text
    */
    String getCurrentTextSelection() {
        return panel.getCurrentComponent().getTextForSelection();
    }

    @Override
    public void domainObjectChanged(DomainObjectChangedEvent event) {

        if (blockSet != null) {
            if (event.containsEvent(DomainObject.DO_OBJECT_SAVED) ||
                event.containsEvent(DomainObject.DO_DOMAIN_FILE_CHANGED)) {
                // drop all changes

                blockSet.setByteBlockChangeManager(new ByteBlockChangeManager(blockSet));
                updateManager.update();
            }
        }

        if (event.containsEvent(DomainObject.DO_OBJECT_RESTORED) ||
            event.containsEvent(ChangeManager.DOCR_MEMORY_BLOCK_CHANGED) ||
            event.containsEvent(ChangeManager.DOCR_MEMORY_BLOCK_ADDED) ||
            event.containsEvent(ChangeManager.DOCR_MEMORY_BLOCK_MOVED) ||
            event.containsEvent(ChangeManager.DOCR_MEMORY_BLOCK_REMOVED) ||
            event.containsEvent(ChangeManager.DOCR_MEMORY_BLOCKS_JOINED) ||
            event.containsEvent(ChangeManager.DOCR_MEMORY_BLOCK_SPLIT)) {

            // call plugin to update data models
            memoryConfigurationChanged();
            return; // memoryConfigurationChanged will recreate the
            // changeManager, so get out now.
        }

        if (event.containsEvent(ChangeManager.DOCR_MEMORY_BYTES_CHANGED) ||
            event.containsEvent(ChangeManager.DOCR_CODE_ADDED) ||
            event.containsEvent(ChangeManager.DOCR_MEM_REFERENCE_ADDED)) {
            updateManager.update();
        }
    }

    private ProgramByteBlockSet getByteBlockSet(ByteBlockChangeManager changeManager) {
        if (program == null) {
            return null;
        }

        return new ProgramByteBlockSet(this, program, changeManager);
    }

    public void setByteBlocks(ByteBlockChangeManager changeManager) {
        if (blockSet != null) {
            blockSet.dispose();
        }

        blockSet = getByteBlockSet(changeManager);
        if (plugin.isDisposed() == true) {
            return;
        }

        panel.setByteBlocks(blockSet);
    }

    @Override
    void updateSelection(ByteBlockSelection selection) {
        ProgramSelectionPluginEvent event = blockSet.getPluginEvent(plugin.getName(), selection);
        currentSelection = event.getSelection();
        plugin.updateSelection(this, event, program);
        clipboardProvider.setSelection(currentSelection);
        contextChanged();
    }

    @Override
    void updateLocation(ByteBlock block, BigInteger blockOffset, int column, boolean export) {
        ProgramLocationPluginEvent event =
            blockSet.getPluginEvent(plugin.getName(), block, blockOffset, column);
        if (event == null) {
                this.plugin.dispose();
                return;
            }
        currentLocation = event.getLocation();
        plugin.updateLocation(this, event, export);
        clipboardProvider.setLocation(currentLocation);
        contextChanged();
    }

    void readDataState(SaveState saveState) {
        unRegisterNavigatable();
        initializeInstanceID(saveState.getLong("NAV_ID", getInstanceID()));
        registerNavigatable();
        restoreLocation(saveState);
    }

    void restoreLocation(SaveState saveState) {
        int blockNumber = saveState.getInt(BLOCK_NUM, 0);
        BigInteger blockOffset = new BigInteger(saveState.getString(BLOCK_OFFSET, "0"));
        int column = saveState.getInt(BLOCK_COLUMN, 0);

        int index = saveState.getInt(INDEX, 0);
        int xOffset = saveState.getInt(X_OFFSET, 0);
        int yOffset = saveState.getInt(Y_OFFSET, 0);
        ViewerPosition vp = new ViewerPosition(index, xOffset, yOffset);

        ByteBlock[] blocks = getByteBlocks();
        if (blocks != null && blockNumber>= 0 && blockNumber <blocks.length) {
            ByteViewerState view = new ByteViewerState(blockSet,
                new ByteBlockInfo(blocks[blockNumber], blockOffset, column), vp);
            panel.returnToView(view);
        }
    }

    Object getUndoRedoState(DomainObject domainObject) {
        if (program != domainObject || blockSet == null) {
            return null;
        }
        return blockSet.getUndoRedoState();
    }

    void restoreUndoRedoState(DomainObject domainObject, Object state) {
        if (program != domainObject || blockSet == null) {
            return;
        }
        SaveState saveState = (SaveState) state;
        blockSet.restoreUndoReoState(saveState);
    }

    void writeDataState(SaveState saveState) {
        saveState.putLong("NAV_ID", getInstanceID());
        ByteBlockInfo info = panel.getCursorLocation();
        int blockNumber = -1;
        String blockOffset = "0";
        int column = 0;

        if (info != null) {
            blockNumber = getBlockNumber(info);
            blockOffset = info.getOffset().toString();
            column = info.getColumn();
        }
        saveState.putInt(BLOCK_NUM, blockNumber);
        saveState.putString(BLOCK_OFFSET, blockOffset);
        saveState.putInt(BLOCK_COLUMN, column);

        ViewerPosition vp = panel.getViewerPosition();
        saveState.putInt(INDEX, vp.getIndexAsInt());
        saveState.putInt(X_OFFSET, vp.getXOffset());
        saveState.putInt(Y_OFFSET, vp.getYOffset());

    }

    private int getBlockNumber(ByteBlockInfo info) {
        ByteBlock[] blocks = getByteBlocks();
        ByteBlock b = info.getBlock();
        for (int i = 0; i <blocks.length; i++) {
            if (blocks[i] == b) {
                return i;
            }
        }
        return -1;
    }

    @Override
    public DataFormatModel getDataFormatModel(String formatName) {
        DataFormatModel dataFormatModel = super.getDataFormatModel(formatName);
        if (dataFormatModel instanceof ProgramDataFormatModel) {
            ((ProgramDataFormatModel) dataFormatModel).setProgram(program);
        }
        return dataFormatModel;
    }

    @Override
    void setEditMode(boolean isEditable) {
        super.setEditMode(isEditable);
        enablePaste(isEditable);
    }

    @Override
    void dispose() {
        if (program != null) {
            program.removeListener(this);
        }
        program = null;
        setByteBlocks(null);
        if (clipboardService != null) {
            clipboardService.deRegisterClipboardContentProvider(clipboardProvider);
        }
        disposed = true;
        unRegisterNavigatable();
        super.dispose();
    }

    @Override
    protected Set<DataFormatModel> getDataFormatModels() {
        Set<DataFormatModel> dataFormatModels = super.getDataFormatModels();
        List<ProgramDataFormatModel> instances =
            ClassSearcher.getInstances(ProgramDataFormatModel.class);
        dataFormatModels.addAll(instances);
        return dataFormatModels;
    }

//==================================================================================================
// Inner Classes
//==================================================================================================

    private class CloneByteViewerAction extends DockingAction {

        public CloneByteViewerAction() {
            super("ByteViewer Clone", plugin.getName());
            ImageIcon image = ResourceManager.loadImage("images/camera-photo.png");
            setToolBarData(new ToolBarData(image, "ZZZ"));

            setDescription("Create a snapshot (disconnected) copy of this Bytes window ");
            setHelpLocation(new HelpLocation("Snapshots", "Snapshots_Start"));
            setKeyBindingData(new KeyBindingData(KeyEvent.VK_T,
                InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK));
        }

        @Override
        public void actionPerformed(ActionContext context) {
            ProgramByteViewerComponentProviderEmu newProvider =
                new ProgramByteViewerComponentProviderEmu(tool, plugin, false);

            plugin.addProvider(newProvider);
            SaveState saveState = new SaveState();
            writeConfigState(saveState);
            newProvider.readConfigState(saveState);

            tool.showComponentProvider(newProvider, true);


            newProvider.doSetProgram(program);


            newProvider.setLocation(currentLocation);
            newProvider.setSelection(currentSelection, false);
            newProvider.setHighlight(currentHighlight);
            ViewerPosition viewerPosition = panel.getViewerPosition();
            newProvider.panel.setViewerPosition(viewerPosition);

        }
    }

    @Override
    public void addNavigatableListener(NavigatableRemovalListener listener) {
        navigationListeners.add(listener);
    }

    @Override
    public void removeNavigatableListener(NavigatableRemovalListener listener) {
        navigationListeners.remove(listener);
    }

    void registerNavigatable() {
        NavigatableRegistry.registerNavigatable(tool, this);
    }

    void unRegisterNavigatable() {
        NavigatableRegistry.unregisterNavigatable(tool, this);
        for (NavigatableRemovalListener listener : navigationListeners) {
            listener.navigatableRemoved(this);
        }
    }

    void setClipboardService(ClipboardService service) {
        clipboardService = service;
        if (clipboardService != null) {
            clipboardService.registerClipboardContentProvider(clipboardProvider);
        }
    }

    @Override
    public void removeHighlightProvider(ListingHighlightProvider highlightProvider, Program p) {
        // currently unsupported
    }

    @Override
    public void setHighlightProvider(ListingHighlightProvider highlightProvider, Program p) {
        // currently unsupported

    }
}
