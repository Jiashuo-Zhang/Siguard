""" Plugin implementations

This module contains the implementation of some features

- benchmarking
- pruning
"""
from siguard.laser.plugin.plugins.benchmark import BenchmarkPluginBuilder
from siguard.laser.plugin.plugins.coverage.coverage_plugin import CoveragePluginBuilder
from siguard.laser.plugin.plugins.dependency_pruner import DependencyPrunerBuilder
from siguard.laser.plugin.plugins.mutation_pruner import MutationPrunerBuilder
from siguard.laser.plugin.plugins.call_depth_limiter import CallDepthLimitBuilder
from siguard.laser.plugin.plugins.instruction_profiler import InstructionProfilerBuilder
