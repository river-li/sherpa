# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Context

This is the SHERPA project - an LLM-powered fuzzing tool developed for DARPA's AI Cyber Challenge (AIxCC). It automates security vulnerability discovery in OSS-Fuzz projects by targeting high-value, attacker-controlled entry points with generated fuzz harnesses.

## Common Development Commands

### SHERPA Setup & Execution
```bash
# Initial setup (creates venv, installs dependencies)
make setup

# Clean environment (removes venv, jobs/, __pycache__)
make clean

# Run fuzzing for specific target (requires OPENAI_API_KEY env var)
export OPENAI_API_KEY="your-key"
export DOCKER_DEFAULT_PLATFORM=linux/amd64  # Required for Apple Silicon
make leveldb

# Manual execution with batch_generate.py
source .venv/bin/activate
python harness_generator/batch_generate.py --targets harness_generator/yamls/leveldb.yaml

# Fuzz unharnessed repositories
python harness_generator/src/fuzz_unharnessed_repo.py --repo <git-url>

# Run utility scripts
make run-script SCRIPT=generate_reports.py
```

### Python Development
```bash
# Activate virtual environment
source .venv/bin/activate

# Install/upgrade dependencies
pip install -r harness_generator/requirements.txt

# Run individual components
python harness_generator/src/harness_generator.py --project <name> --oss-fuzz-path <path>
```

## High-Level Architecture

### Core Pipeline Components

The SHERPA pipeline consists of interconnected Python modules that work together through a multi-stage process:

1. **batch_generate.py**: Entry point that orchestrates multiple harness generation runs
   - Loads project configurations from YAML files (`yamls/`)
   - Clones OSS-Fuzz repositories to `jobs/` directory
   - Invokes HarnessGenerator for each project with configurable rounds
   - Manages parallel execution threads and logging

2. **HarnessGenerator** (src/harness_generator.py): Main workflow engine
   - **Baseline Build**: Compiles existing fuzzers to record current state
   - **Harness Creation**: Uses CodexHelper to generate new `LLVMFuzzerTestOneInput` functions
   - **Build-Fix Loop**: Iteratively fixes compilation errors (max retries configurable)
   - **Corpus Generation**: Creates meaningful seed inputs based on harness analysis
   - **Fuzzing Execution**: Runs fuzzers and captures crashes/timeouts
   - **Crash Analysis**: Reproduces crashes and generates bug reports

3. **CodexHelper** (src/codex_helper.py): LLM interaction wrapper
   - Manages pseudo-terminal sessions with the Codex CLI
   - Implements retry logic for transient API failures
   - Monitors for completion sentinel (`./done` file)
   - Enforces timeouts with graceful shutdown (SIGINT→SIGTERM→SIGKILL)
   - Returns captured output or None if no edits made

### Data Flow & State Management

```
yamls/*.yaml → batch_generate.py → jobs/<uuid>/
                                    ├── harness_round_<n>.log
                                    ├── crash_info.md
                                    ├── crash_analysis.md
                                    └── oss-fuzz/ (cloned repo)
```

The system maintains state through:
- Git repositories for tracking code changes
- Job directories with unique UUIDs for each run
- Round-based logging for debugging failed attempts
- Crash artifacts with reproduction commands

### Key Design Patterns

1. **Two-Phase Filtering**: Prevents false positives through:
   - Ex-ante prompt engineering (targets public APIs, honors preconditions)
   - Ex-post LLM crash analysis (filters harness-induced bugs)

2. **Iterative Refinement**: Build failures trigger automatic fixes via LLM
   - Compiler errors sent back to Codex with context
   - Limited retries prevent infinite loops
   - Git diffs track all changes

3. **Resource Management**:
   - Docker containers for isolated fuzzing environments
   - Configurable timeouts and memory limits
   - Clean teardown of processes and temporary files

## Project Structure Focus

Key directories to understand:
- `harness_generator/src/`: Core Python modules (harness_generator.py, codex_helper.py)
- `harness_generator/yamls/`: Target project configurations
- `harness_generator/scripts/`: Analysis and reporting utilities
- `jobs/`: Runtime output directory (created on first run)
- `leveldb_writeup/`: Complete case study demonstrating methodology

## Environment Variables

Required for operation:
- `OPENAI_API_KEY`: OpenAI API key for LLM operations
- `DOCKER_DEFAULT_PLATFORM`: Set to `linux/amd64` on Apple Silicon
- `OSS_FUZZ_PATH`: Optional path to existing OSS-Fuzz checkout

## Security Context

This codebase is designed for defensive security research. Key principles:
- Targets real attack surfaces (file parsers, network protocols)
- Follows responsible disclosure with 90-day windows
- Generates maintainer-ready reports with CWE mapping
- Filters false positives through multi-stage validation