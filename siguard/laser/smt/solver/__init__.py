import z3

from siguard.laser.smt.solver.solver import Solver, Optimize, BaseSolver
from siguard.laser.smt.solver.independence_solver import IndependenceSolver
from siguard.laser.smt.solver.solver_statistics import SolverStatistics
from siguard.support.support_args import args

if args.parallel_solving:
    z3.set_param("parallel.enable", True)
