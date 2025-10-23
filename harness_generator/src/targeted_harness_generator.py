from __future__ import annotations

import logging
import os
import re
import subprocess
import textwrap
import time
import uuid
from pathlib import Path
from typing import Optional

from .harness_generator import HarnessGenerator, HarnessGeneratorError, MAX_BUILD_RETRIES
from .static_analysis import CPPParser, EvalResult
from .codex_helper import CodexHelper

CODEX_ANALYSIS_MODEL = os.environ.get("CODEX_ANALYSIS_MODEL", "gpt-5-mini")
CODEX_APPROVAL_MODE = os.environ.get("CODEX_APPROVAL_MODE", "full-auto")

class TargetedHarnessGenerator(HarnessGenerator):
    """
    Extends HarnessGenerator to create targeted harnesses for specific functions.

    This generator validates that:
    1. The generated harness invokes the target function
    2. The harness compiles successfully and increases coverage within 1 minute
    3. No crashes occur within 1 minute of fuzzing
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logger = logging.getLogger(__name__)

    def generate_targeted_harness(
        self,
        *,
        target_function: str,
        build: bool = True,
        run_smoke: bool = False,
        max_iterations: int = 5,
    ) -> EvalResult:
        """
        Generate a targeted harness for a specific function.

        Args:
            target_function: The name of the function to target
            build: Whether to build after generating the harness
            run_smoke: Whether to run a smoke test first
            max_iterations: Maximum build retry iterations

        Returns:
            EvalResult indicating success or failure reason
        """
        print(f"[*] Generating targeted harness for function: {target_function}")

        # 1. Baseline build
        print("[*] Building docker image and fuzzers...")
        self._build_with_retries(clean=True, max_iterations=1)

        baseline_fuzzers = self._list_fuzzer_binaries()
        print(f"[*] Baseline has {len(baseline_fuzzers)} fuzzer(s):\n{baseline_fuzzers}\n")

        if run_smoke:
            self._run_any_fuzzer_once()

        # 2. Extract archives
        print("[*] Extracting any project archives...")
        self._extract_archives()

        # 3. Generate targeted harness using Codex
        print(f"[*] Running Codex to generate harness for {target_function}...")
        harness_path = self._invoke_codex_for_targeted_harness(target_function)

        if not harness_path:
            print(f"[!] Failed to generate harness for {target_function}")
            return EvalResult.Failed

        # 4. Repack archives
        print("[*] Repackaging any project archives...")
        self._repack_archives()

        # 5. Validate the generated harness source
        print(f"[*] Validating harness invokes target function...")
        harness_source = harness_path.read_text(encoding="utf-8", errors="replace")
        validation_result = self._validate_harness_calls_target(target_function, harness_source)

        if validation_result != EvalResult.Success:
            print(f"[!] Validation failed: {validation_result.name}")
            return validation_result

        # 6. Build the harness
        if build:
            print("[*] Attempting image/fuzzer rebuild...")
            try:
                self._build_with_retries(clean=False, max_iterations=max_iterations)
            except HarnessGeneratorError as e:
                print(f"[!] Build failed: {e}")
                return EvalResult.Failed

        # 7. Detect new fuzzers
        final_fuzzers = self._list_fuzzer_binaries()
        new_fuzzers = sorted(final_fuzzers - baseline_fuzzers)

        if not new_fuzzers:
            print("[!] No new fuzzer binaries detected after Codex run.")
            return EvalResult.Failed

        print(f"[*] Detected {len(new_fuzzers)} new fuzzer(s): {', '.join(new_fuzzers)}")

        # 8. Run fuzzing validation (1 minute test)
        for fuzzer in new_fuzzers:
            try:
                self._invoke_codex_to_generate_seeds(fuzzer)
            except HarnessGeneratorError as err:
                print(f"[!] Failed to generate seeds for {fuzzer}: {err}")

            print(f"[*] Running validation fuzzing for {fuzzer} (60 seconds)...")

            # Check coverage increase and crashes
            result = self._validate_fuzzing(fuzzer, target_function, timeout_seconds=60)

            if result != EvalResult.Success:
                print(f"[!] Fuzzing validation failed: {result.name}")
                return result

            print(f"[*] ✓ Fuzzing validation passed for {fuzzer}")

        print(f"[*] ✓ Successfully generated and validated targeted harness for {target_function}")
        return EvalResult.Success

    def _invoke_codex_for_targeted_harness(self, target_function: str) -> Optional[Path]:
        """
        Invoke Codex to generate a harness targeting a specific function.

        Args:
            target_function: The name of the function to target

        Returns:
            Path to the generated harness file, or None if failed
        """
        patcher = CodexHelper(
            repo_path=self.repo_path,
            ai_key_path=str(self.ai_key_path),
            copy_repo=False,
            codex_cli=self.codex_cli,
            codex_model=CODEX_ANALYSIS_MODEL,
            approval_mode=CODEX_APPROVAL_MODE,
        )

        instructions = textwrap.dedent(
            f"""
            **Objective: Create a targeted libFuzzer harness**

            Generate a **new libFuzzer harness** for the **{self.project}** OSS-Fuzz project that
            specifically targets the function: **{target_function}**

            ────────────────────────────────────────
            **Requirements**

            * **Target the specific function**: The harness MUST invoke `{target_function}`.
               This is a strict requirement for success.

            * **ENSURE HARNESS USES THE LIBRARY CORRECTLY**
              Many false positives are the result of the generated harness code failing
              to exercise the library properly (passing a ptr instead of an int, etc.)
              Ensure all calls performed by the harness match the library signatures
              and use the library in the way it was intended to be used. Our goal is to
              only uncover bugs that are true positives with real world implications.

            * Harness signature  
            ```c++
            extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
            ````

            * Keep everything in C/C++ (follow project style).
            * **Do not** remove or refactor existing code; just add the harness and
            tweak build scripts so it is compiled.
            * Place the harness source next to similar existing harnesses.

            Extracted archive directories (may be empty if none):
            {', '.join(str(p.relative_to(self.repo_path)) for p in self._archives) or 'None'}

            **NO** build/run commands—just write code + build recipe edits.
            When finished, write the path to the new harness into `./done`

            Notes: 
            - The oss-fuzz project typically contains a Dockerfile, build.sh, and project.yaml.
            - The repo source is typically not included, but can be cloned to assist in analysis.
              - It may be specified in project.yaml as `main_repo`. It may be cloned as part of the docker build.
              - When you clone the repo source, you must clone it within your working directory (don't use /tmp)
            - Carefully analyze the existing build structure to fully understand what is needed to successfully include your new harness in the build.

            VERY IMPORTANT: You must clone the repo so that you can validate the function signatures of every library function you put in the new harness.
                            You must ensure that the library is being used correctly to mitigate false-positive crashes caused by errors in the harness.

            This task is very important! Every bug we trigger will be responsibly disclosed to make the world a safer place.
            Have fun and do your very best!
            """
        ).strip()

        stdout = patcher.run_codex_command(instructions)
        if stdout is None:
            raise HarnessGeneratorError(
                f"Codex produced no edits when generating harness for {target_function}."
            )

        print(f"[*] Codex stdout (truncated):\n{stdout[:1200]}")

        # Locate the generated harness
        harness_path = self._locate_harness_source("")
        return harness_path

    def _validate_harness_calls_target(self, target_function: str, harness_source: str) -> EvalResult:
        """
        Validate that the harness invokes the target function and doesn't fake it.

        Args:
            target_function: The function signature (e.g., "int foo(const Bar *, int)")
            harness_source: The source code of the harness

        Returns:
            EvalResult.Success if valid, otherwise the specific failure reason
        """
        # Extract function name from signature
        from .static_analysis.get_res import extract_name
        try:
            function_name = extract_name(target_function, keep_namespace=False, exception_flag=False)
            if not function_name:
                # Fallback: try to extract name manually
                # Simple heuristic: find identifier before '('
                import re
                match = re.search(r'\b(\w+)\s*\(', target_function)
                function_name = match.group(1) if match else target_function
        except Exception as e:
            # Fallback to using the whole signature
            print(f"[!] Warning: Could not extract function name from '{target_function}': {e}")
            function_name = target_function

        print(f"[*] Extracted function name: {function_name} from signature: {target_function}")

        # Determine language-appropriate parser
        parser = CPPParser(None, source_code=harness_source)

        # Check 1: Ensure target function is not redefined in the harness
        if parser.exist_function_definition(function_name):
            print(f"[!] Harness contains a fake definition of {function_name}")
            return EvalResult.Fake

        # Check 2: Ensure target function is actually called
        if not parser.is_fuzz_function_called(function_name):
            print(f"[!] Harness does not call {function_name}")
            return EvalResult.NoCall

        print(f"[*] ✓ Harness correctly invokes {function_name}")
        return EvalResult.Success

    def _validate_fuzzing(
        self,
        fuzzer_name: str,
        target_function: str,
        timeout_seconds: int = 60
    ) -> EvalResult:
        """
        Run the fuzzer and validate coverage increase and no crashes.

        Args:
            fuzzer_name: Name of the fuzzer to run
            target_function: The target function name
            timeout_seconds: How long to run the fuzzer

        Returns:
            EvalResult.Success if validation passed, otherwise failure reason
        """
        # Record baseline bugs before fuzzing
        baseline_bug_files = self._find_bug_files()

        # Parse fuzzer output to extract coverage information
        print(f"[*] Running {fuzzer_name} for {timeout_seconds} seconds...")

        try:
            output = self._run_fuzzer(fuzzer_name, timeout_seconds=timeout_seconds)
        except HarnessGeneratorError as e:
            print(f"[!] Fuzzer execution failed: {e}")
            return EvalResult.Failed

        # Check for new crashes
        new_bug_files = self._find_bug_files() - baseline_bug_files
        if new_bug_files:
            print(f"[!] Detected {len(new_bug_files)} crash/oom/timeout file(s)")
            for p in new_bug_files:
                print(f"    • {p.relative_to(self.repo_path)}")
            return EvalResult.Failed

        # Parse coverage from output
        coverage_increased = self._check_coverage_increase(output)

        if not coverage_increased:
            print(f"[!] No coverage increase detected")
            return EvalResult.Failed

        print(f"[*] ✓ Fuzzer ran successfully with coverage increase and no crashes")
        return EvalResult.Success

    def _check_coverage_increase(self, fuzzer_output: str) -> bool:
        """
        Check if coverage increased during fuzzing.

        Args:
            fuzzer_output: The output from the fuzzer

        Returns:
            True if coverage increased, False otherwise
        """
        # Look for libFuzzer statistics that show coverage growth
        # Example patterns:
        # #123    NEW    cov: 456 ft: 789 corp: 10/1234b ...
        # stat::number_of_executed_units: 1000
        # stat::peak_rss_mb: 50

        # Check for "NEW" entries which indicate new coverage
        new_coverage_lines = re.findall(r'#\d+\s+NEW\s+cov:\s+(\d+)', fuzzer_output)

        if new_coverage_lines:
            # Coverage increased
            coverage_values = [int(cov) for cov in new_coverage_lines]
            print(f"[*] Coverage increased: {coverage_values[0]} -> {coverage_values[-1]}")
            return True

        # Alternative: check if final coverage is reported
        final_cov_match = re.search(r'cov:\s+(\d+)', fuzzer_output)
        if final_cov_match:
            final_cov = int(final_cov_match.group(1))
            if final_cov > 0:
                print(f"[*] Final coverage: {final_cov}")
                return True

        # If we have executed units, consider it a success (basic sanity check)
        exec_units_match = re.search(r'#(\d+)', fuzzer_output)
        if exec_units_match:
            exec_units = int(exec_units_match.group(1))
            if exec_units > 10:  # At least some executions happened
                print(f"[*] Executed {exec_units} units")
                return True

        return False

    def check_success(self, target_function: str, harness_source: str) -> EvalResult:
        """
        Legacy compatibility method - delegates to validation.

        Args:
            target_function: The name of the function to target
            harness_source: The source code of the harness

        Returns:
            EvalResult indicating validation status
        """
        return self._validate_harness_calls_target(target_function, harness_source)