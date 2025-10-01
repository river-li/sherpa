
from _pytest.python import defaultdict
import tree_sitter_cpp
from constants import EvalResult
from cpp_parser import CPPParser
# from agent_tools.code_tools.parsers.c_parser import CParser
from pathlib import Path
from tree_sitter import Language, Parser
import json


def get_language_info(work_dir: Path) -> str:

    yaml_file = work_dir / "benchmark.yaml"
    if yaml_file.exists():
        with open(yaml_file, "r") as f:
            import yaml
            cfg = yaml.safe_load(f)
            lang = cfg.get("language", "none")
            return lang
    return "none"

def _strip_templates(name: str) -> str:
    """Remove all balanced < … > template arguments, preserving :: separators."""
    out:list[str] = [] 
    depth = 0
    for ch in name:
        if ch == '<':
            depth += 1                      # enter template-argument list
        elif ch == '>':
            depth -= 1                      # leave   "
        elif depth == 0:
            out.append(ch)                  # keep only when *not* inside <>
    return ''.join(out).replace(' ', '')    # also drop stray spaces


def extract_name(function_signature: str, keep_namespace: bool=False, exception_flag: bool=True)-> str:

    if  "N/A" in function_signature:
        return "N/A"
    lang = Language(tree_sitter_cpp.language())
    parser = Parser(lang)

    function_signature = function_signature.strip()
    if not function_signature.endswith(";"):
        function_signature += ";"
    # a patch, replace a
    function_signature = function_signature.replace("(anonymous namespace)::", "") # type: ignore
    
    # Parse the function signature
    # Note: The parser expects a byte string, so we encode the string to bytes
    tree = parser.parse( function_signature.encode('utf-8'))

    # Find the function declaration node
    query_str = """
    (function_declarator
        [
            (qualified_identifier)@function_name
            (identifier) @function_name
        ]
    )
    """
    query = lang.query(query_str)
    captures = query.captures(tree.root_node)
    if not captures:
        if exception_flag: 
            raise ValueError(f"Function signature '{function_signature}' does not contain a valid function declaration.")
        else:
            return ""
    if len(captures) > 1:
        if exception_flag:
            raise ValueError(f"Function signature '{function_signature}' contains multiple function declarations, expected only one.")
        else:
            return ""

    full_name = captures["function_name"][0]
    
    # remove templates
    stripped_name = _strip_templates(full_name.text.decode('utf-8')) # type: ignore
    if not keep_namespace:
        # split the function name by :: and remove the namespace
        if "::" in stripped_name:
            stripped_name = stripped_name.split("::")[-1]
    return stripped_name
            
 
def get_enhanced_res(save_path: Path, n_run: int=1, enhanced_flag: bool=True):


    res_data: dict[str, EvalResult] = {}
    lang_count: dict[str, int] = defaultdict(int)
    for work_dir in save_path.iterdir():
        if not work_dir.is_dir():
            continue
        res_dir = work_dir / "status"/ f"0{n_run}" / "result.json"

        if not res_dir.exists():
            print(f"Result file {res_dir} does not exist, skip")
            res_data[work_dir.name] = EvalResult.NoLogError
            continue

        with res_dir.open("r") as f:
            try:
                res_json = json.load(f)
            except json.JSONDecodeError:
                res_data[work_dir.name] = EvalResult.NoLogError
                print(f"Result file {res_dir} is not a valid json, skip")
                continue

        fuzz_target_source = ""
        harness_dir = work_dir / "fixed_targets"
        for file in harness_dir.iterdir():
            if file.is_file() and file.suffix in [".cpp", ".c", ".cc", ".cxx"]:
                with file.open("r") as f:
                    fuzz_target_source = f.read()
                break
        if not fuzz_target_source:
            res_data[work_dir.name] = EvalResult.NoSource
            continue

        # get function signature
        import yaml 

        yaml_file = work_dir / "benchmark.yaml"
        if not yaml_file.exists():
            res_data[work_dir.name] = EvalResult.NoYaml
            continue
        with yaml_file.open("r") as f:
            bench_data = yaml.safe_load(f)
            function_signature = bench_data.get("functions", "")[0]["signature"]
            function_name = extract_name(function_signature)

        semantic_error = res_json.get("semantic_error", "")
        crash_flag = res_json.get("crashes", False)

        if crash_flag and semantic_error == "NO_SEMANTIC_ERR":
            # print(f"{work_dir.name} has crash but no semantic error, mark as Failed")
            res_data[work_dir.name] = EvalResult.Failed
            continue

        if semantic_error == "NO_SEMANTIC_ERR":
            parser = CPPParser(None, source_code=fuzz_target_source)

            if parser.exist_function_definition(function_name):
                res_data[work_dir.name] = EvalResult.Fake
                continue
            
            if not parser.is_fuzz_function_called(function_name):
                res_data[work_dir.name] = EvalResult.NoCall
                continue
            # get language info
            lang = get_language_info(work_dir)
            lang_count[lang] += 1
            res_data[work_dir.name] = EvalResult.Success
        else:
            res_data[work_dir.name] = EvalResult.Failed
        
    # sort the result by key
    res_data = dict(sorted(res_data.items(), key=lambda item: item[0]))
    #save the result to txt file
    with (save_path / "run{}_res_{}.txt".format(n_run, enhanced_flag)).open("w") as f:
        for k, v in res_data.items():
            f.write(f"{k}: {v.name}\n")
        
        # count the number of each result
        from collections import Counter
        counter = Counter(res_data.values())
        f.write("\n")
        f.write("Summary:\n")
        for k, v in counter.items():
            f.write(f"{k.name}: {v}\n")

        # write the language count
        f.write("\n")
        f.write("Language Summary:\n")
        for k, v in lang_count.items():
            f.write(f"{k}: {v}\n")
            
    return res_data

 
get_enhanced_res(Path("/home/yk/code/fuzz-introspector/scripts/oss-fuzz-gen-e2e/workdir/oss-fuzz-gen/results/localFI/function0/try1"), n_run=1, enhanced_flag=True)