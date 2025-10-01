from .harness_generator import HarnessGenerator

class TargetedHarnessGenerator(HarnessGenerator):
    def generate_targeted_harness(self, *, target_function: str, build: bool = True, run_smoke: bool = False, max_iterations: int = ...) -> None:
        pass