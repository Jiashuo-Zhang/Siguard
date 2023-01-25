import imp
from siguard.analysis.module.base import DetectionModule, EntryPoint
from siguard.analysis.module.modules.StatelessSignatureVerification import StatelessSignatureVerification
from siguard.support.support_utils import Singleton
from siguard.support.support_args import args


from siguard.analysis.module.modules.UnseparatedSigningDomain import UnsepararedSigningDomain
from siguard.analysis.module.modules.dependence_on_predictable_vars import (
    PredictableVariables,
)

from siguard.analysis.module.modules.state_change_external_calls import (
    StateChangeAfterCall,
)

from siguard.analysis.module.base import EntryPoint

from siguard.exceptions import DetectorNotFoundError

from typing import Optional, List


class ModuleLoader(object, metaclass=Singleton):
    """ModuleLoader

    The module loader class implements a singleton loader for detection modules.

    By default it will load the detection modules in the mythril package.
    Additional detection modules can be loaded using the register_module function call implemented by the ModuleLoader
    """

    def __init__(self):
        self._modules = []
        self._register_mythril_modules()

    def register_module(self, detection_module: DetectionModule):
        """Registers a detection module with the module loader"""
        if not isinstance(detection_module, DetectionModule):
            raise ValueError("The passed variable is not a valid detection module")
        self._modules.append(detection_module)

    def get_detection_modules(
        self,
        entry_point: Optional[EntryPoint] = None,
        white_list: Optional[List[str]] = None,
    ) -> List[DetectionModule]:
        """Gets registered detection modules

        :param entry_point: If specified: only return detection modules with this entry point
        :param white_list: If specified: only return whitelisted detection modules
        :return: The selected detection modules
        """

        result = self._modules[:]

        if white_list:

            # Sanity check

            available_names = [type(module).__name__ for module in result]

            for name in white_list:
                if name not in available_names:
                    raise DetectorNotFoundError(
                        "Invalid detection module: {}".format(name)
                    )

            result = [
                module for module in result if type(module).__name__ in white_list
            ]
        if args.use_integer_module is False:
            result = [
                module
                for module in result
                if type(module).__name__ != "IntegerArithmetics"
            ]
        if entry_point:
            result = [module for module in result if module.entry_point == entry_point]

        return result

    def _register_mythril_modules(self):
        
        self._modules.extend(
            [   
                UnsepararedSigningDomain(),
                StatelessSignatureVerification(),
            ]
        )
