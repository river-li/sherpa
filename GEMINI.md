## Project Overview

This project, SHERPA (Security Harness Engineering for Robust Program Analysis), is a tool that uses Large Language Models (LLMs) to automatically generate fuzzing harnesses for C/C++ projects. It is designed to find security vulnerabilities in real-world software by targeting high-level, attacker-controlled entry points.

The core of the project is the `harness_generator.py` script, which automates the entire workflow:

1.  **Target Selection:** An LLM analyzes the target project to identify unfuzzed, high-value entry points.
2.  **Harness Generation:** The LLM generates a new libFuzzer harness for the selected target.
3.  **Build & Fix:** The script attempts to build the new harness. If the build fails, the compiler errors are sent back to the LLM to automatically fix the code.
4.  **Fuzzing:** The new harness is fuzzed to find crashes.
5.  **Crash Analysis:** When a crash is found, the LLM analyzes the crash report to determine the root cause and provide a summary of the bug.

The project uses Docker to create a consistent build environment and integrates with OSS-Fuzz projects.

## Building and Running

### Environment Setup

1.  **Install Dependencies:**
    ```bash
    make setup
    ```
    This command creates a Python virtual environment in `.venv` and installs the required dependencies from `harness_generator/requirements.txt`.

2.  **Set OpenAI API Key:**
    An OpenAI API key is required for the LLM to function. You can set it as an environment variable:
    ```bash
    export OPENAI_API_KEY="your-api-key-here"
    ```

### Running the Harness Generator

*   **Run on a specific project (e.g., leveldb):**
    ```bash
    make leveldb
    ```
    This will run the harness generator on the `leveldb` project, using the configuration from `harness_generator/yamls/leveldb.yaml`.

*   **Run in batch mode:**
    ```bash
    python harness_generator/batch_generate.py --targets harness_generator/yamls/c-projects.yaml
    ```

*   **Fuzz a single, unharnessed repository:**
    ```bash
    python harness_generator/src/fuzz_unharnessed_repo.py --repo <git-url>
    ```

## Development Conventions

*   **Configuration:** Projects are configured using YAML files located in the `harness_generator/yamls/` directory.
*   **Python:** The project is written in Python and uses a virtual environment for dependency management.
*   **LLM Interaction:** All interaction with the LLM is handled by the `CodexHelper` class in `harness_generator/src/codex_helper.py`. The prompts sent to the LLM are detailed and specific, guiding the model to produce high-quality code and analysis.
*   **Output:** The output of the process, including generated harnesses, crash reports, and analysis, is stored in the project's working directory. The `leveldb_writeup` directory provides a good example of the generated artifacts.
*   **Testing:** The project seems to be tested by running it on real-world projects like `leveldb`. There is no dedicated test suite apparent from the file structure.
