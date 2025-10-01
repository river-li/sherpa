from .harness_generator import HarnessGenerator
from .static_analysis import CParser, CPPParser, EvalResult

class TargetedHarnessGenerator(HarnessGenerator):
    def generate_targeted_harness(
        self,
        *,
        target_function: str,
        build: bool = True,
        run_smoke: bool = False,
        max_iterations: int = ...,
    ) -> None:
        pass

    def check_success(self, target_function: str, harness_source: str) -> EvalResult:
        parser = CPPParser(None, source_code=harness_source)

        if parser.exist_function_definition(target_function):
            return EvalResult.Fake
        
        if not parser.is_fuzz_function_called(target_function):
            return EvalResult.NoCall
        
        # check whether the coverage is increased


        return EvalResult.Success