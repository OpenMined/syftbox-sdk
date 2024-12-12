import yaml
from syftbox.lib import Client
import yaml
from pathlib import Path
from ..exceptions import (
    DatasetNotFoundError,
    DatasetConfigNotFoundError,
    DatasetVersionMismatchError,
)

from .utils import validate_dataset_entry, execute_data_loader

REQUIRED_DATASET_VERSION = "0.1.0"


def load_dataset(dataset_name: str) -> Path:
    """
    Attempts to load a dataset by its path from the CONFIG.

    Steps:
    1. Validate each dataset to ensure they have mandatory fields.
    2. Search for the dataset with a matching path.
    3. If found, return its path as a pathlib.Path object.
    4. If not found, raise DatasetNotFoundError.
    """

    client = Client.load()

    datasets_config_path: Path = client.my_datasite / "datasets" / "datasets.yaml"

    dataset_config = None

    with open(datasets_config_path, "r") as dataset_config_file:
        dataset_config = yaml.safe_load(dataset_config_file)

    # Check if the dataset.yaml was properly loaded
    if dataset_config is None:
        raise DatasetConfigNotFoundError("dataset.yaml not found on this datasite.")

    if "version" in dataset_config:
        dataset_version = dataset_config["version"]
        if dataset_version != REQUIRED_DATASET_VERSION:
            raise DatasetVersionMismatchError(
                f"Dataset config  version '{dataset_version}' does not match the required version '{REQUIRED_DATASET_VERSION}'."
            )
    else:
        raise DatasetVersionMismatchError(
            f"Dataset config file doesn't have a version."
        )

    # First, ensure the config structure is as expected.
    if "datasets" not in dataset_config or not isinstance(
        dataset_config["datasets"], list
    ):
        raise DatasetValidationError(
            "The configuration file is missing the 'datasets' list."
        )

    # Validate all datasets upfront (fail early if something is wrong).
    for dataset in dataset_config["datasets"]:
        validate_dataset_entry(dataset)

    # Try to match the requested dataset_name
    for dataset in dataset_config["datasets"]:
        if dataset_name == dataset["name"]:
            dataset_path = Path(dataset["path"])
            data_loader_path = dataset["dataset_loader"]
            dataset = execute_data_loader(data_loader_path, dataset_path)
            return dataset

    # If we exit the loop, no dataset matched
    raise DatasetNotFoundError(f"The dataset with name '{dataset_name}' was not found.")
