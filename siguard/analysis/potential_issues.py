
import imp
from opcode import hascompare
from siguard.analysis.report import Issue
from siguard.analysis.issue_annotation import IssueAnnotation
from siguard.analysis.solver import get_transaction_sequence
from siguard.exceptions import UnsatError
from siguard.laser.ethereum.state.annotation import StateAnnotation
from siguard.laser.ethereum.state.global_state import GlobalState
from siguard.laser.smt import And
from siguard.support.support_args import args
import logging
from siguard.laser.ethereum.util import getCallData, getReadAndWriteStorage,getCalldataRelatedR_W,isSloadVar,sloadAnnotions,getStorage,getHashsInMem,hasSStoreAnnotation,getPotentialNonce,getCalldataRelatedNonce,getEcrecoverRelatedNonce
from siguard.laser.ethereum.call import EcrecoverReturnValue

log = logging.getLogger(__name__)


class PotentialIssue:
    """Representation of a potential issue"""

    def __init__(
        self,
        contract,
        function_name,
        address,
        swc_id,
        title,
        bytecode,
        detector,
        severity=None,
        description_head="",
        description_tail="",
        constraints=None,
        globalState=None,
        hashAnnotations=None,
        transaction_sequence=None
    ):
        """

        :param contract: The contract
        :param function_name: Function name where the issue is detected
        :param address: The address of the issue
        :param swc_id: Issue's corresponding swc-id
        :param title: Title
        :param bytecode: bytecode of the issue
        :param detector: The detector the potential issue belongs to
        :param gas_used: amount of gas used
        :param severity: The severity of the issue
        :param description_head: The top part of description
        :param description_tail: The bottom part of the description
        :param constraints: The non-path related constraints for the potential issue
        """
        self.title = title
        self.contract = contract
        self.function_name = function_name
        self.address = address
        self.description_head = description_head
        self.description_tail = description_tail
        self.severity = severity
        self.swc_id = swc_id
        self.bytecode = bytecode
        self.constraints = constraints or []
        self.detector = detector
        self.globalState=globalState
        self.hashAnnotations=hashAnnotations
        self.transaction_sequence=transaction_sequence


class PotentialIssuesAnnotation(StateAnnotation):
    def __init__(self):
        self.potential_issues = []

    @property
    def search_importance(self):
        return 100 * len(self.potential_issues)

    # def persist_over_calls(self) -> bool:
    #     return True


def get_potential_issues_annotation(state: GlobalState) -> PotentialIssuesAnnotation:
    """
    Returns the potential issues annotation of the given global state, and creates one if
    one does not already exist.

    :param state: The global state
    :return:
    """
    for annotation in state.annotations:
        if isinstance(annotation, PotentialIssuesAnnotation):
            return annotation

    annotation = PotentialIssuesAnnotation()
    state.annotate(annotation)
    return annotation


def check_potential_issues(state: GlobalState) -> None:
    
    """
    Called at the end of a transaction, checks potential issues, and
    adds valid issues to the detector.

    :param state: The final global state of a transaction
    :return:
    """
    
    annotation = get_potential_issues_annotation(state)
    unsat_potential_issues = []
    log.debug("Check Potential Issues")

    for potential_issue in annotation.potential_issues:
        if potential_issue.swc_id == '003':
            if hasSStoreAnnotation(state.annotations)==False:
                log.info("No state Change, Ignore Unsepareted Signing Domain,Continue")
                continue 
        if potential_issue.swc_id == '005':
            if hasSStoreAnnotation(state.annotations)==False:
                log.info("No state Change, Ignore Stateless Signature Verification,Continue")
                continue 
            hashes = potential_issue.hashAnnotations
            hashStorage=set()
            hashCalldata=set()
            for h in hashes:
                hashStorage = hashStorage | set(getStorage([h.data]))
                hashCalldata = hashCalldata | set(getCallData([h.data]))
            
            nonceStorage = set(getPotentialNonce(state.annotations))
            calldataR_W = set(getCalldataRelatedR_W(state.annotations))
            calldataNonce = set(getCalldataRelatedNonce(state.annotations))

            ecrecoverNonce = set(getEcrecoverRelatedNonce(state.annotations))

            log.info("Nonce-related Storage Slot:"+str(nonceStorage))
            log.info("Hash-Related Storage Slot:"+str(hashStorage))
            log.info("Hash-raleted Calldata Offset:"+str(hashCalldata))
            log.info("Storage-related Calldata Offset:"+str(calldataR_W))
            log.info("Ecrecover Return Value Related Nonce:"+str(ecrecoverNonce))

            if len(list(hashStorage & nonceStorage))>=1 or len(list(hashCalldata & calldataNonce))>=1 or len(ecrecoverNonce)>=1 :
                log.info("Hash is related to nonce, The Signature cannot be Replay, Continue")
                continue
        log.info("Find Issue:"+str(potential_issue.title))
        issue = Issue(
            contract=potential_issue.contract,
            function_name=potential_issue.function_name,
            address=potential_issue.address,
            title=potential_issue.title,
            bytecode=potential_issue.bytecode,
            swc_id=potential_issue.swc_id,
            gas_used=(state.mstate.min_gas_used, state.mstate.max_gas_used),
            severity=potential_issue.severity,
            description_head=potential_issue.description_head,
            description_tail=potential_issue.description_tail,
            transaction_sequence=potential_issue.transaction_sequence,
        )
        state.annotate(
            IssueAnnotation(
                detector=potential_issue.detector,
                issue=issue,
                conditions=[
                    And(*(state.world_state.constraints + potential_issue.constraints))
                ],
            )
        )
        if args.use_issue_annotations is False:
            potential_issue.detector.issues.append(issue)
            potential_issue.detector.update_cache([issue])
    annotation.potential_issues = unsat_potential_issues
