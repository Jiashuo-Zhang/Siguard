"""This module contains various utility conversion functions and constants for
LASER."""
from doctest import Example
import imp
import re
import numbers
from typing import Dict, List, Union, TYPE_CHECKING, cast
#from siguard.laser.ethereum.state.global_state import GlobalState

if TYPE_CHECKING:
    from siguard.laser.ethereum.state.machine_state import MachineState

from siguard.laser.smt import BitVec, Bool, Expression, If, simplify, symbol_factory
from siguard.laser.ethereum.state.annotation import StateAnnotation
TT256 = 2**256
TT256M1 = 2**256 - 1
TT255 = 2**255
import logging

log = logging.getLogger(__name__)

def safe_decode(hex_encoded_string: str) -> bytes:
    """

    :param hex_encoded_string:
    :return:
    """
    if hex_encoded_string.startswith("0x"):
        return bytes.fromhex(hex_encoded_string[2:])
    else:
        return bytes.fromhex(hex_encoded_string)


def to_signed(i: int) -> int:
    """

    :param i:
    :return:
    """
    return i if i < TT255 else i - TT256


def get_instruction_index(
    instruction_list: List[Dict], address: int
) -> Union[int, None]:
    """

    :param instruction_list:
    :param address:
    :return:
    """
    index = 0
    for instr in instruction_list:
        if instr["address"] >= address:
            return index
        index += 1
    return None


def get_trace_line(instr: Dict, state: "MachineState") -> str:
    """

    :param instr:
    :param state:
    :return:
    """
    stack = str(state.stack[::-1])
    # stack = re.sub("(\d+)",   lambda m: hex(int(m.group(1))), stack)
    stack = re.sub("\n", "", stack)
    return str(instr["address"]) + " " + instr["opcode"] + "\tSTACK: " + stack


def pop_bitvec(state: "MachineState") -> BitVec:
    """

    :param state:
    :return:
    """
    # pop one element from stack, converting boolean expressions and
    # concrete Python variables to BitVecVal

    item = state.stack.pop()

    if isinstance(item, Bool):
        return If(
            cast(Bool, item),
            symbol_factory.BitVecVal(1, 256),
            symbol_factory.BitVecVal(0, 256),
        )
    elif isinstance(item, int):
        return symbol_factory.BitVecVal(item, 256)
    else:
        item = cast(BitVec, item)
        return simplify(item)


def get_concrete_int(item: Union[int, Expression]) -> int:
    """

    :param item:
    :return:
    """
    if isinstance(item, int):
        return item
    elif isinstance(item, BitVec):
        if item.symbolic:
            raise TypeError("Got a symbolic BitVecRef")
        return item.value
    elif isinstance(item, Bool):
        value = item.value
        if value is None:
            raise TypeError("Symbolic boolref encountered")
        return value

    assert False, "Unhandled type {} encountered".format(str(type(item)))


def concrete_int_from_bytes(
    concrete_bytes: Union[List[Union[BitVec, int]], bytes], start_index: int
) -> int:
    """

    :param concrete_bytes:
    :param start_index:
    :return:
    """
    concrete_bytes = [
        byte.value if isinstance(byte, BitVec) and not byte.symbolic else byte
        for byte in concrete_bytes
    ]
    integer_bytes = concrete_bytes[start_index : start_index + 32]

    # The below statement is expected to fail in some circumstances whose error is caught
    return int.from_bytes(integer_bytes, byteorder="big")  # type: ignore


def concrete_int_to_bytes(val):
    """

    :param val:
    :return:
    """
    # logging.debug("concrete_int_to_bytes " + str(val))
    if type(val) == int:
        return val.to_bytes(32, byteorder="big")
    return simplify(val).value.to_bytes(32, byteorder="big")


def bytearray_to_int(arr):
    """

    :param arr:
    :return:
    """
    o = 0
    for a in arr:
        o = (o << 8) + a
    return o


def extract_copy(
    data: bytearray, mem: bytearray, memstart: int, datastart: int, size: int
):
    for i in range(size):
        if datastart + i < len(data):
            mem[memstart + i] = data[datastart + i]
        else:
            mem[memstart + i] = 0


def extract32(data: bytearray, i: int) -> int:
    """

    :param data:
    :param i:
    :return:
    """
    if i >= len(data):
        return 0
    o = data[i : min(i + 32, len(data))]
    o.extend(bytearray(32 - len(o)))
    return bytearray_to_int(o)


def isSloadVar(s:BitVec)-> bool:
    from siguard.laser.ethereum.instructions import SLoadAnnotation

    for i in s.annotations:
        if isinstance(i,SLoadAnnotation):
            return True
    return False

def hasAddressVar(s:BitVec)-> bool:
    from siguard.laser.ethereum.instructions import ContractAddressAnnotation

    for i in s._annotations:
        if isinstance(i,ContractAddressAnnotation):
            return True
    return False

def isSstoreVar(s:BitVec) -> bool:
    from siguard.laser.ethereum.instructions import SStoreAnnotation

    for i in s.annotations:
        if isinstance(i,SStoreAnnotation):
            return True
    return False

def isHashVar(h:BitVec) ->bool:
    from siguard.laser.ethereum.instructions import HashAnnotation

    for i in h.annotations:
        if isinstance(i,HashAnnotation):
            return True
    return False
def isCalldataVar(s:BitVec) ->bool:
    from siguard.laser.ethereum.instructions import CallDataAnnotation
    result=[]
    for i in s.annotations:
        if isinstance(i,CallDataAnnotation):
            return True
    return False
def calldataAnnotions(s:BitVec) -> List[StateAnnotation]:
    from siguard.laser.ethereum.instructions import CallDataAnnotation
    result=[]
    for i in s.annotations:
        if isinstance(i,CallDataAnnotation):
            result.append(i)
    return result
def sloadAnnotions(s:BitVec) -> List[StateAnnotation]:
    from siguard.laser.ethereum.instructions import SLoadAnnotation

    result=[]
    for i in s.annotations:
        if isinstance(i,SLoadAnnotation):
            result.append(i)
    return result
def sstoreAnnotions(s:BitVec) -> List[StateAnnotation]:
    from siguard.laser.ethereum.instructions import SStoreAnnotation

    result=[]
    for i in s.annotations:
        if isinstance(i,SStoreAnnotation):
            result.append(i)
    return result

def ecrecoverAnnotions(s:BitVec) -> List[Union[BitVec,int]]:
    from siguard.laser.ethereum.call import EcrecoverReturnValue
    result=[]
    for i in s.annotations:
        if isinstance(i,EcrecoverReturnValue):
            result.append(i.value)
    return result

def hashAnnotions(s:BitVec) -> List[StateAnnotation]:
    from siguard.laser.ethereum.instructions import HashAnnotation

    result=[]
    for i in s.annotations:
        if isinstance(i,HashAnnotation):
            result.append(i)
    return result
def EcrecoverReturnValueAnnotations (s:BitVec) -> List[StateAnnotation]:
    from siguard.laser.ethereum.call import EcrecoverReturnValue
    result=[]
    for i in s.annotations:
        if isinstance(i,EcrecoverReturnValue):
            result.append(i)
    return result

def CopyAllAnnotation(mem):
    from siguard.laser.ethereum.instructions import HashAnnotation

    todo = mem
    result=[]
    while todo:
        expr = todo.pop()
        if isinstance(expr,BitVec):
            result.extend(expr.annotations)
    for i in result:
        if isinstance(i,HashAnnotation):
            result.extend(i.data.annotations)
            result=list(set(result))

    return list(set(result))
def hasAddress(mem):
    todo=mem
    hasAddress=False
    while todo:
        if hasAddress:
            break
        expr = todo.pop()
        if isinstance(expr,BitVec) and hasAddressVar(expr):
            hasAddress=True
        
        for i in range (expr.num_args()):  
            todo.append(expr.arg(i))
    return hasAddress
def getCallData(mem):
    from siguard.laser.ethereum.instructions import CallDataAnnotation
    '''
    Input: BitVec List
    Output: CallData Related to these BitVecs 
    (These BitVecs are calculated based on values of these slot)
    '''
    allAnnotations=CopyAllAnnotation(mem)
    calldata=[]
    for i in allAnnotations:
        if isinstance(i,CallDataAnnotation):
                for j in range (0,i.size):
                    calldata.append(i.slot+j)

    return list(set(calldata))

def getEcrecoverReturnValue(mem):
    todo=mem
    ecrecover=[]
    while todo:
        expr = todo.pop()
        if isinstance(expr,BitVec) :
            ecrecover.extend(EcrecoverReturnValueAnnotations(expr))
            
    return ecrecover
def hasSStoreAnnotation(annotations:List[StateAnnotation])->bool :
    from siguard.laser.ethereum.instructions import SStoreAnnotation

    for a in annotations:
        if isinstance(a,SStoreAnnotation):
            return True
    return False

def getStorage(mem):
    '''
    Input: BitVec List
    Output: Storage-Slot Related to these BitVecs 
    (These BitVecs are calculated based on values of these slot)
    '''
    todo=mem
    storage=[]
    while todo:
        expr = todo.pop()
        if isinstance(expr,BitVec) and isSloadVar(expr):
            for i in sloadAnnotions(expr):
                storage.append(i.slot)

    return storage

def getHashsInMem(mem)->List[StateAnnotation]:
    todo=mem
    hashs=[]
    while todo:
        expr = todo.pop()
        if isinstance(expr,BitVec) and isHashVar(expr):
            hashs.extend(hashAnnotions(expr))
        
    return list(set(hashs))
def trytoGetMemoryWord(annotations:List[StateAnnotation],idx: Union[BitVec,int]) -> List[Union[BitVec,int]]:
    from siguard.laser.ethereum.instructions import MemoryStoreWordAnnotation
    annotations.reverse()
    for a in annotations:
        if isinstance(a,MemoryStoreWordAnnotation):
                if a.slot==idx:
                    return [a.value]
                if isinstance(a.slot,BitVec) and isinstance(idx,BitVec):
                    if (a.slot-idx).value==0:
                        return [a.value]

    return [0]
            
                    
def getEIP712Storage(annotations:List[StateAnnotation]) -> List[int]:
    from siguard.laser.ethereum.instructions import StorageEIP712SeperatorAnnotation
    storageList=[]
    for a in annotations:
        if isinstance(a,StorageEIP712SeperatorAnnotation):
            storageList.append(a.slot)
    return storageList

def getCalldataRelatedNonce(annotations:List[StateAnnotation]) -> List[int]:
    nonce = getPotentialNonce(annotations)
    calldata=getCallData(nonce)
    return calldata

def getEcrecoverRelatedNonce(annotations: List[StateAnnotation])-> List[int]:
    nonce = getPotentialNonce(annotations)
    ecrecover = getEcrecoverReturnValue(nonce)
    return ecrecover

def getCalldataRelatedR_W(annotations:List[StateAnnotation]) -> List[int]:
    r_w = getReadAndWriteStorage(annotations)
    calldata=getCallData(r_w)
    return calldata

def getReadAndWriteStorage(annotations:List[StateAnnotation]) -> List[int]:
    from siguard.laser.ethereum.instructions import SLoadAnnotation,SStoreAnnotation
    readset=dict()
    writeset=dict()
    for a in annotations:
        if isinstance(a,SLoadAnnotation):
            readset[a.slot]=a.value
        if isinstance(a,SStoreAnnotation):
            writeset[a.slot]=a.value
    r=readset.keys()
    w=writeset.keys()
    r_w=list(set(r)&set(w))
    return r_w

def getPotentialNonce(annotations:List[StateAnnotation]) -> List[int]:
    from siguard.laser.ethereum.instructions import SLoadAnnotation,SStoreAnnotation
    '''
    Input: global_state.annotations
    Output: Nonce-related Storage Slot. 
    '''
    readset=dict()
    writeset=dict()
    nonceList=[]
    for a in annotations:
        if isinstance(a,SLoadAnnotation):
            readset[a.slot]=a.value
        if isinstance(a,SStoreAnnotation):
            writeset[a.slot]=a.value
    r=readset.keys()
    w=writeset.keys()

    r_w=list(set(r)&set(w))
    for i in r_w:
        if isinstance(writeset[i]-readset[i],numbers.Number):
            try: 
                nonceList.append(i)
            except Exception as e:
                continue
        else:
            if isinstance(writeset[i]-readset[i],BitVec):
                if (writeset[i]-readset[i]).value is not None:
                    nonceList.append(i)
            #print(type(writeset[i]-readset[i]))
    return nonceList