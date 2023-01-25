from siguard.laser.plugin.signals import PluginSkipState
from siguard.laser.plugin.interface import LaserPlugin
from siguard.laser.plugin.builder import PluginBuilder
from siguard.laser.ethereum.state.global_state import GlobalState
from siguard.laser.ethereum.svm import LaserEVM


class CallDepthLimitBuilder(PluginBuilder):
    name = "call-depth-limit"

    def __call__(self, *args, **kwargs):
        return CallDepthLimit(kwargs["call_depth_limit"])


class CallDepthLimit(LaserPlugin):
    def __init__(self, call_depth_limit: int):
        self.call_depth_limit = call_depth_limit

    def initialize(self, symbolic_vm: LaserEVM):
        """Initializes the mutation pruner

        Introduces hooks for SSTORE operations
        :param symbolic_vm:
        :return:
        """

        @symbolic_vm.pre_hook("CALL")
        def sstore_mutator_hook(global_state: GlobalState):
            if len(global_state.transaction_stack) - 1 == self.call_depth_limit:
                #log.info("Reach CALL Depth Limit, Skip State")
                raise PluginSkipState
