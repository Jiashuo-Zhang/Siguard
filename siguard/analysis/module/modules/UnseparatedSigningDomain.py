"""This module contains the detection code for precompiled contract
calls."""
from siguard.analysis.report import Issue
from siguard.analysis import solver
from siguard.analysis.potential_issues import (
    PotentialIssue,
    get_potential_issues_annotation,
)
from siguard.analysis.issue_annotation import IssueAnnotation

from siguard.analysis.swc_data import REENTRANCY
from siguard.laser.ethereum.state.constraints import Constraints
from siguard.laser.ethereum.transaction.symbolic import ACTORS
from siguard.analysis.module.base import DetectionModule, EntryPoint
from siguard.laser.smt import UGT, symbol_factory, Or, BitVec
from siguard.laser.ethereum.natives import PRECOMPILE_COUNT
from siguard.laser.ethereum.state.global_state import GlobalState
from siguard.exceptions import UnsatError
from copy import copy
import logging
import numbers
from siguard.laser.ethereum import util

from siguard.laser.ethereum.util import getHashsInMem, getStorage,hasAddress,hasAddressVar,trytoGetMemoryWord,getEIP712Storage,hasSStoreAnnotation
from siguard.laser.ethereum.instructions import HashAnnotation

from siguard.laser.smt import (
    BitVec,
    symbol_factory,
)
log = logging.getLogger(__name__)

DESCRIPTION = """

Search for Unseparared Signing Domain

"""




def _is_ecrecover_call(global_state: GlobalState):
    to = global_state.mstate.stack[-2]  # type: BitVec
    if to.value == 1:
        return True
    else:
        return False



class UnsepararedSigningDomain(DetectionModule):

    name = "Stateless Signature Verification"
    swc_id = "003"
    description = DESCRIPTION
    entry_point = EntryPoint.CALLBACK
    pre_hooks = ["STATICCALL","CALL","DELEGATECALL","CALLCODE"]
    def _execute(self, state: GlobalState) -> None:
        """

        :param state:
        :return:
        """
        
        potential_issues = self._analyze_state(state)

        annotation = get_potential_issues_annotation(state)
        annotation.potential_issues.extend(potential_issues)

    def _analyze_state(self, state: GlobalState):
        """

        :param state:
        :return:
        """

        op_code = state.get_current_instruction()["opcode"]
        if op_code=="STATICCALL" or op_code=="DELEGATECALL":
            mstart,offset = state.mstate.stack[-3], state.mstate.stack[-4]
        elif op_code=='CALL' or op_code=="CALLCODE": 
            mstart,offset = state.mstate.stack[-4], state.mstate.stack[-5]

        
        to=state.mstate.stack[-2]
        constraints=[]
        if _is_ecrecover_call(state):    
            memdata = list(set([state.mstate.memory[mstart + i] for i in range(0,32)]))
            if len(memdata)==1 and memdata[0]==0:
                memdata = trytoGetMemoryWord(state.annotations,mstart)
            if len(memdata)==1 and memdata[0]==0:
                log.debug("Failed to get Memory Word")
                return []

            hashes = getHashsInMem(memdata)

            for h in hashes:
                hashStorages=set(getStorage([h.data]))
                EIP712Storage=set(getEIP712Storage(state.world_state.annotations))
                EipHash=list(hashStorages&EIP712Storage)
                log.debug(EIP712Storage)
                if(len(EipHash)>=1) or hasAddressVar(h.data):
                    log.info("Hash Has EIP Seperator or Contract Address, The Signature cannot be Replayed")
                    return []
                
        else:
            log.debug("Not Ecrecover, Finish")
            return []
       



        address = state.get_current_instruction()["address"]

        try:
            constraints = Constraints(constraints)

            transaction_sequence = solver.get_transaction_sequence(
                state, constraints + state.world_state.constraints
            )

            description_head = "Unseparared Signing Domain"
            description_tail = (
                "Unseparared Signing Domain"
            )

            
            issue = PotentialIssue(
                contract=state.environment.active_account.contract_name,
                function_name=state.environment.active_function_name,
                address=address,
                swc_id="003",
                bytecode=state.environment.code.bytecode,
                title="SignatureReplay",
                severity="High",
                description_head=description_head,
                description_tail=description_tail,
                constraints=constraints,
                detector=self,
                globalState=state,
                hashAnnotations=hashes,
                transaction_sequence=transaction_sequence,
            )
            

        except UnsatError:
            logging.debug("[Unseparared Signing Domain] No model found.")
            return []
        except Exception as e:
            return []
        logging.debug("Finind Potentail Issue:"+"Unseparared Signing Domain")
        return [issue]


detector = UnsepararedSigningDomain()
