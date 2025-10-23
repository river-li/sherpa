#!/usr/bin/env python3

"""
batch_generate_target.py
────────────────────────

Orchestrates batch execution of targeted fuzzing harness generation against
multiple OSS-Fuzz projects using the benchmark YAML format.

Key differences from batch_generate.py:
• Consumes YAML files from the benchmark/ directory with function metadata
• Each YAML file contains:
  - functions: list of target functions with signatures and metadata
  - project: OSS-Fuzz project name
  - target_name: existing fuzzer target name
  - target_path: path to existing harness
  - language: programming language (c++, c, etc.)

• For each function, it:
  1. Clones the OSS-Fuzz repository
  2. Invokes TargetedFuzzingGenerator for each function
  3. Logs all output to function-specific log files

This batch driver is designed to work with the new targeted_fuzzing.py script,
which generates harnesses for specific functions rather than auto-selecting them.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import logging
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Dict, List

import yaml
from dotenv import load_dotenv
from git import Repo, exc as git_exc

# ---------------------------------------------------------------------------#
# Constants & global state
# ---------------------------------------------------------------------------#
OUTPUT_ROOT = Path("./jobs").resolve()
OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)

# Default OSS-Fuzz repository
DEFAULT_OSS_FUZZ_URL = "git@github.com:google/oss-fuzz.git"
DEFAULT_OSS_FUZZ_REF = "master"

# ---------------------------------------------------------------------------#
# YAML helper
# ---------------------------------------------------------------------------#

def load_benchmark_yaml(path: Path) -> Dict:
    """
    Load a benchmark YAML file and return its contents.
    Expected format:
      functions:
        - name: mangled_function_name
          signature: human-readable signature
          params: [...]
          return_type: ...
      project: project_name
      target_name: existing_fuzzer_name
      target_path: /path/to/harness.cc
      language: c++
    """
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    if not data:
        raise ValueError(f"Empty YAML file: {path}")

    # Validate required fields
    if "functions" not in data or not data["functions"]:
        raise ValueError(f"YAML must contain a 'functions' list: {path}")

    if "project" not in data:
        raise ValueError(f"YAML must contain 'project' field: {path}")

    return data


def load_all_benchmarks(benchmark_dir: Path) -> List[Dict]:
    """Load all YAML files from the benchmark directory."""
    benchmarks = []

    if not benchmark_dir.is_dir():
        raise ValueError(f"Benchmark directory not found: {benchmark_dir}")

    for yaml_file in sorted(benchmark_dir.glob("*.yaml")):
        try:
            data = load_benchmark_yaml(yaml_file)
            data["_source_file"] = yaml_file.name
            benchmarks.append(data)
        except Exception as err:
            logging.warning("Skipping %s: %s", yaml_file.name, err)

    return benchmarks


# ---------------------------------------------------------------------------#
# Git helper
# ---------------------------------------------------------------------------#

def clone_and_checkout(url: str, ref: str, dest: Path) -> Repo:
    """Clone OSS-Fuzz repository and checkout the specified reference."""
    logging.info("Cloning %s → %s", url, dest)
    repo = Repo.clone_from(url, dest)
    try:
        repo.git.checkout(ref)
    except git_exc.GitCommandError:
        repo.git.fetch("origin", ref)
        repo.git.checkout("FETCH_HEAD")
    logging.info("Checked-out commit %s", repo.head.commit.hexsha)
    return repo


# ---------------------------------------------------------------------------#
# Worker function
# ---------------------------------------------------------------------------#

def process_benchmark(
    benchmark: Dict,
    *,
    ai_key_path: Path,
    sanitizer: str,
    oss_fuzz_url: str,
    oss_fuzz_ref: str,
    scratch_space: Path | None,
    copy_repo: bool,
    no_build: bool,
    max_retries: int,
    fuzzer_timeout: int,
) -> None:
    """
    Process a single benchmark YAML file.
    For each function in the benchmark, generate a targeted harness.
    """
    project = benchmark["project"]
    functions = benchmark["functions"]
    source_file = benchmark.get("_source_file", "unknown")

    logging.info(
        "[%s] Processing %d function(s) from %s",
        project,
        len(functions),
        source_file
    )

    # Create a run directory for this benchmark
    run_dir = OUTPUT_ROOT / f"{project}_{uuid.uuid4().hex[:8]}"
    run_dir.mkdir(parents=True, exist_ok=True)

    # Clone OSS-Fuzz repository
    try:
        clone_and_checkout(oss_fuzz_url, oss_fuzz_ref, run_dir)
    except Exception as err:
        logging.error("[SKIP] %s - clone/checkout failed: %s", project, err)
        return

    # Keep only the target project directory under oss-fuzz/projects/
    projects_root = run_dir / "projects"
    if projects_root.is_dir():
        for sub in projects_root.iterdir():
            if sub.is_dir() and sub.name != project:
                try:
                    shutil.rmtree(sub)
                except Exception as exc:
                    logging.warning(
                        "[%s] Failed to remove directory %s: %s",
                        project,
                        sub,
                        exc,
                    )

    # Import the TargetedHarnessGenerator
    try:
        # Add necessary directories to path
        parent_dir = Path(__file__).parent
        src_dir = parent_dir / "src"
        static_analysis_dir = src_dir / "static_analysis"

        for path in [str(parent_dir), str(src_dir), str(static_analysis_dir)]:
            if path not in sys.path:
                sys.path.insert(0, path)

        # Import using absolute imports
        from src.targeted_harness_generator import TargetedHarnessGenerator
        from src.static_analysis import EvalResult
    except ImportError as e:
        logging.error("[%s] Failed to import TargetedHarnessGenerator: %s", project, e)
        import traceback
        logging.debug(traceback.format_exc())
        return

    # Process each function
    for idx, func in enumerate(functions, 1):
        func_name = func.get("name", f"function_{idx}")
        func_signature = func.get("signature", func_name)

        logging.info(
            "[%s] Function %d/%d: %s",
            project,
            idx,
            len(functions),
            func_signature[:80]  # Truncate long signatures
        )

        # Create a sanitized function name for the log file
        log_safe_name = func_signature.replace("/", "_").replace(" ", "_").replace("*", "p")[:50]
        if not log_safe_name or log_safe_name.startswith("_Z"):
            log_safe_name = f"func_{idx}"

        log_path = run_dir / f"targeted_{log_safe_name}_{idx}.log"

        # Create the TargetedHarnessGenerator
        try:
            generator = TargetedHarnessGenerator(
                project_name=project,
                oss_fuzz_path=run_dir,
                ai_key_path=ai_key_path,
                sanitizer=sanitizer,
                scratch_space=scratch_space,
                copy_repo=copy_repo,
            )

            logging.info("[%s] Running targeted harness generation → %s", project, log_path.name)

            # Redirect stdout/stderr to log file
            import sys as _sys
            old_stdout = _sys.stdout
            old_stderr = _sys.stderr

            # Retry loop: try up to 3 times to generate a successful harness
            max_attempts = 3
            result = EvalResult.Failed

            for attempt in range(1, max_attempts + 1):
                logging.info("[%s] Function %d: Attempt %d/%d", project, idx, attempt, max_attempts)

                # Append to log file for each attempt
                mode = "a" if attempt > 1 else "w"

                try:
                    with open(log_path, mode, encoding="utf-8") as lf:
                        _sys.stdout = lf
                        _sys.stderr = lf

                        if attempt > 1:
                            print(f"\n{'='*80}")
                            print(f"RETRY ATTEMPT {attempt}/{max_attempts}")
                            print(f"{'='*80}\n")

                        # Run the generation with build retries set to max_retries (5)
                        result = generator.generate_targeted_harness(
                            target_function=func_signature,
                            build=not no_build,
                            max_iterations=max_retries,  # This is build_with_retry attempts (5)
                        )

                finally:
                    _sys.stdout = old_stdout
                    _sys.stderr = old_stderr

                # Check if successful
                if result == EvalResult.Success:
                    logging.info("[%s] Function %d: SUCCESS on attempt %d", project, idx, attempt)
                    break
                else:
                    logging.warning("[%s] Function %d: Attempt %d failed with %s", project, idx, attempt, result.name)

                    # If this is not the last attempt, continue to retry
                    if attempt < max_attempts:
                        logging.info("[%s] Function %d: Retrying...", project, idx)

            # Final report after all attempts
            if result != EvalResult.Success:
                logging.warning("[%s] Function %d: FAILED after %d attempts (final: %s)", project, idx, max_attempts, result.name)

        except Exception as e:
            logging.error(
                "[%s] Function %d failed with exception: %s. See %s",
                project,
                idx,
                str(e),
                log_path,
            )

    logging.info("[%s] All functions processed → %s", project, run_dir)


# ---------------------------------------------------------------------------#
# Main
# ---------------------------------------------------------------------------#

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Batch-generate targeted fuzzing harnesses from benchmark YAML files.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--benchmark-dir",
        type=Path,
        default=Path("./benchmark"),
        help="Directory containing benchmark YAML files",
    )

    parser.add_argument(
        "--benchmark-file",
        type=Path,
        help="Process a single benchmark YAML file instead of the entire directory",
    )

    parser.add_argument(
        "--project-filter",
        type=str,
        help="Only process benchmarks for this project name",
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=1,
        help="Maximum number of concurrent benchmark processing jobs",
    )

    parser.add_argument(
        "--ai-key-path",
        type=Path,
        help="Path to file containing OpenAI API key (or use OPENAI_API_KEY env var)",
    )

    parser.add_argument(
        "--sanitizer",
        default="address",
        help="Sanitizer to use when building fuzzers",
    )

    parser.add_argument(
        "--oss-fuzz-url",
        default=DEFAULT_OSS_FUZZ_URL,
        help="OSS-Fuzz git repository URL",
    )

    parser.add_argument(
        "--oss-fuzz-ref",
        default=DEFAULT_OSS_FUZZ_REF,
        help="OSS-Fuzz git reference to checkout",
    )

    parser.add_argument(
        "--scratch-space",
        type=Path,
        help="Directory for temporary files",
    )

    parser.add_argument(
        "--copy-repo",
        action="store_true",
        help="Work on a copy of the repository",
    )

    parser.add_argument(
        "--no-build",
        action="store_true",
        help="Skip docker rebuild step (for debugging)",
    )

    parser.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="Maximum build-fix retry attempts",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Fuzzer timeout in seconds",
    )

    parser.add_argument(
        "--randomize",
        action="store_true",
        help="Randomize the order of benchmarks before processing",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        default=True,
        help="Enable DEBUG logging",
    )

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    # Load environment variables (for OPENAI_API_KEY)
    if args.ai_key_path and args.ai_key_path.exists():
        load_dotenv(args.ai_key_path)
    else:
        load_dotenv()

    # Verify API key is available
    if not os.environ.get("OPENAI_API_KEY") and not args.ai_key_path:
        logging.warning(
            "OPENAI_API_KEY not found in environment. "
            "Make sure it's set or use --ai-key-path"
        )

    # Load benchmarks
    benchmarks: List[Dict] = []

    if args.benchmark_file:
        # Process a single file
        logging.info("Loading single benchmark file: %s", args.benchmark_file)
        try:
            data = load_benchmark_yaml(args.benchmark_file)
            data["_source_file"] = args.benchmark_file.name
            benchmarks.append(data)
        except Exception as err:
            logging.error("Failed to load %s: %s", args.benchmark_file, err)
            sys.exit(1)
    else:
        # Process entire directory
        logging.info("Loading benchmarks from: %s", args.benchmark_dir)
        benchmarks = load_all_benchmarks(args.benchmark_dir)

    # Apply project filter if specified
    if args.project_filter:
        benchmarks = [b for b in benchmarks if b["project"] == args.project_filter]
        logging.info(
            "Filtered to project '%s': %d benchmark(s)",
            args.project_filter,
            len(benchmarks)
        )

    if not benchmarks:
        logging.error("No benchmarks to process")
        sys.exit(1)

    # Randomize if requested
    if args.randomize:
        import random
        random.shuffle(benchmarks)
        logging.info("--randomize is set; benchmark list shuffled")

    # Calculate total functions
    total_functions = sum(len(b["functions"]) for b in benchmarks)
    logging.info(
        "Loaded %d benchmark(s) with %d total function(s)",
        len(benchmarks),
        total_functions
    )
    logging.info("Running with up to %d concurrent job(s)…", args.threads)

    # Process benchmarks
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = [
            pool.submit(
                process_benchmark,
                b,
                ai_key_path=args.ai_key_path,
                sanitizer=args.sanitizer,
                oss_fuzz_url=args.oss_fuzz_url,
                oss_fuzz_ref=args.oss_fuzz_ref,
                scratch_space=args.scratch_space,
                copy_repo=args.copy_repo,
                no_build=args.no_build,
                max_retries=args.max_retries,
                fuzzer_timeout=args.timeout,
            )
            for b in benchmarks
        ]

        # Wait for all tasks to finish
        for f in concurrent.futures.as_completed(futures):
            try:
                f.result()
            except Exception as exc:
                logging.error("Worker raised: %s", exc)

    logging.info("All work complete.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted - exiting.")
