
import opcode
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
from siguard.laser.ethereum.util import getHashsInMem,trytoGetMemoryWord
from siguard.laser.smt import (
    BitVec,
    symbol_factory,

)
log = logging.getLogger(__name__)

DESCRIPTION = """

Search for Stateless Signature Verification.

"""




def _is_ecrecover_call(global_state: GlobalState):
    to = global_state.mstate.stack[-2]  # type: BitVec
    constraints = copy(global_state.world_state.constraints)
    constraints += [
        Or(
            to < symbol_factory.BitVecVal(1, 256),
            to > symbol_factory.BitVecVal(1, 256),
        )
    ]

    try:
        solver.get_model(constraints)
        return False
    except UnsatError:
        return True



class StatelessSignatureVerification(DetectionModule):

    name = "Stateless Signature Verification"
    swc_id = "005"
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
        else : 
            mstart,offset = state.mstate.stack[-4], state.mstate.stack[-5]

        to=state.mstate.stack[-2]
        constraints=[]
        hashes=[]
        if to.value==1:   
                memdata = list(set([state.mstate.memory[mstart + i] for i in range(0,32)]))
                if len(memdata)<=1:
                    memdata = trytoGetMemoryWord(state.annotations,mstart)
                if len(memdata)==1 and memdata[0]==0:
                    log.debug("Failed to get Memory Word")
                    return []
                hashes = getHashsInMem(memdata)
                  
        else:
            log.debug("Not Ecrecover, Finish")
            return []


        address = state.get_current_instruction()["address"]

        try:
            constraints = Constraints(constraints)

            transaction_sequence = solver.get_transaction_sequence(
                state, constraints + state.world_state.constraints
            )

            description_head = "Single Contract Replay"
            description_tail = (
                " Single Contract Replay"
            )

            issue = PotentialIssue(
                contract=state.environment.active_account.contract_name,
                function_name=state.environment.active_function_name,
                address=address,
                swc_id="005",
                bytecode=state.environment.code.bytecode,
                title="Stateless Signature Verification",
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
            log.debug("[Stateless Signature Verification] No model found.")
            return []
        except Exception as e:
            return []
        logging.info("Find Potential Issue:"+"Stateless Signature Verification")
        return [issue]


detector = StatelessSignatureVerification()
