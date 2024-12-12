import importlib.util
import os
import traceback
from ..exceptions import DataLoderExecutionError, DatasetValidationError
from pathlib import Path
from typing import Any, Dict


def validate_dataset_entry(dataset: Dict[str, Any]) -> None:
    """
    Validate that a dataset entry has all required fields and meets any version requirements.
    Raises DatasetValidationError if mandatory fields are missing.
    Raises DatasetVersionMismatchError if version checking fails.
    """
    # Mandatory fields
    mandatory_fields = ["name", "path", "dataset_loader"]

    for field in mandatory_fields:
        if field not in dataset:
            raise DatasetValidationError(
                f"Mandatory field '{field}' is missing in dataset {dataset.get('name', '(unknown)')}"
            )


def execute_data_loader(file_path: str, dataset_path: Path):
    """
    Load a Python source file as a module and execute a given function from it.

    :param file_path:     The path to the Python source file.
    :param function_name: The name of the function within the module to execute.

    :return: The return value of the called function if successful, or None if errors occur.
    """

    # 2. Check if the file exists
    if not os.path.isfile(file_path):
        raise DataLoderExecutionError(
            f"Error: The file at '{file_path}' does not exist."
        )

    # 3. Attempt to load the module
    module_name = os.path.splitext(os.path.basename(file_path))[0]
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None or spec.loader is None:
        raise DataLoderExecutionError(
            f"Error: Could not create a module specification for '{file_path}'."
        )

    module = importlib.util.module_from_spec(spec)

    try:
        spec.loader.exec_module(module)
    except FileNotFoundError:
        raise DataLoderExecutionError(
            f"Error: The file '{file_path}' was not found or could not be read."
        )
    except SyntaxError as e:
        raise DataLoderExecutionError(
            f"Syntax error encountered when loading '{file_path}': {e}"
        )
    except Exception as e:
        # This is a general catch-all for other unexpected errors during module loading
        traceback.print_exc()
        raise DataLoderExecutionError(
            "An unexpected error occurred when loading the module: {e}"
        )

    # 4. Check if the function is defined in the module
    if not hasattr(module, "load"):
        raise DataLoderExecutionError(
            f"Error: The function 'load' is not defined in the module '{module_name}'."
        )

    func = getattr(module, "load")

    if not callable(func):
        raise DataLoderExecutionError(
            f"Error: 'load' in '{module_name}' is not callable."
        )

    # 5. Try executing the function
    try:
        result = func(dataset_path)
        return result
    except TypeError as e:
        # Argument mismatch errors, etc.
        traceback.print_exc()
        raise DataLoderExecutionError(f"TypeError: {e}")
    except Exception as e:
        # General execution errors
        traceback.print_exc()
        raise DataLoderExecutionError(
            f"An error occurred while executing 'load' from '{file_path}': {e}"
        )
