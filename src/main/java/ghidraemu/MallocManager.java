package ghidraemu;

import java.util.HashMap;
import java.util.Map;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.InsufficientBytesException;

public class MallocManager {
    public AddressSet allocSet;
    public Map<Address, AddressRange> mallocMap = new HashMap<>();
    
    MallocManager(Address rangeStart, int byteSize) throws AddressOverflowException {
        allocSet = new AddressSet(
            new AddressRangeImpl(rangeStart, rangeStart.addNoWrap(byteSize - 1)));
    }

    public Address malloc(int byteLength) throws InsufficientBytesException {
        if (byteLength <= 0) {
            throw new IllegalArgumentException("malloc request for " + byteLength);
        }
        for (AddressRange range : allocSet.getAddressRanges()) {
            if (range.getLength() >= byteLength) {
                AddressRange mallocRange = new AddressRangeImpl(range.getMinAddress(),
                    range.getMinAddress().add(byteLength - 1));
                mallocMap.put(mallocRange.getMinAddress(), mallocRange);
                allocSet.delete(mallocRange);
                return mallocRange.getMinAddress();
            }
        }
        throw new InsufficientBytesException(
            "SimpleMallocMgr failed to allocate " + byteLength + " bytes");
    }

    public void free(Address mallocRangeAddr) {
        AddressRange range = mallocMap.remove(mallocRangeAddr);
        if (range == null) {
            throw new IllegalArgumentException(
                "free request for unallocated block at " + mallocRangeAddr);
        }
        allocSet.add(range);
    }	
}
