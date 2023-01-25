"""This module contains the SMT abstraction for a basic symbol expression."""
from cmath import log
from copy import copy, deepcopy
import imp
from symbol import return_stmt
from typing import Optional, Set, Any, TypeVar, Generic, cast
import z3
#from siguard.laser.ethereum.state.annotation import SLoadAnnotation, SStoreAnnotation


from typing import Union, List,Set, cast, Any, Optional, Callable
import logging
Annotations = Set[Any]
T = TypeVar("T", bound=z3.ExprRef)


class Expression(Generic[T]):
    """This is the base symbol class and maintains functionality for
    simplification and annotations."""

    def __init__(self, raw: T, annotations: Optional[Annotations] = None):
        """

        :param raw:
        :param annotations:
        """
        self.raw = raw

        if annotations:
            assert isinstance(annotations, set)

        self._annotations = annotations or set()
    # def __copy__(self):
    #     ne=Expression(self.raw,copy.deepcopy(self._annotations))
    #     return ne

    @property
    def annotations(self) -> Annotations:
        """Gets the annotations for this expression.

        :return:
        """

        return self._annotations

    def annotate(self, annotation: Any) -> None:
        """Annotates this expression with the given annotation.

        :param annotation:
        """
        #logging.info("Add Annotaion!")
        self._annotations.add(annotation)

    # def isSloadVar(self)-> bool:
    #     for i in self._annotations:
    #         if isinstance(i,SLoadAnnotation):
    #             return True
    #     return False

    # def isSstoreVar(self) -> bool:
    #     for i in self._annotations:
    #         if isinstance(i,SStoreAnnotation):
    #             return True
    #     return False
    
    # def isHashVar(self) ->bool:
    #     for i in self._annotations:
    #         if isinstance(i,HashAnnotation):
    #             return True
    #     return False

    # def sloadAnnotions(self) -> List[SLoadAnnotation]:
    #     result=[]
    #     for i in self.annotations:
    #         if isinstance(i,SLoadAnnotation):
    #             result.append(i)
    #     return result
    # def sstoreAnnotions(self) -> List[SStoreAnnotation]:
    #     result=[]
    #     for i in self.annotations:
    #         if isinstance(i,SStoreAnnotation):
    #             result.append(i)
    #     return result


    def simplify(self) -> None:
        """Simplify this expression."""
        self.raw = cast(T, z3.simplify(self.raw))
    def num_args(self) -> int:
        return self.raw.num_args()
    def arg(self,i):
        return self.raw.arg(i)
    def __repr__(self) -> str:
        return repr(self.raw)
    def is_expr(self) -> bool:
        return z3.is_expr(self.raw)
    def size(self):
        return self.raw.size()

    def __hash__(self) -> int:
        return self.raw.__hash__()

    def get_annotations(self, annotation: Any):
        return list(filter(lambda x: isinstance(x, annotation), self.annotations))


G = TypeVar("G", bound=Expression)


def simplify(expression: G) -> G:
    """Simplify the expression .

    :param expression:
    :return:
    """
    expression.simplify()
    return expression
