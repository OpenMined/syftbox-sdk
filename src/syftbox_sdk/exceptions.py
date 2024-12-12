class DatasetNotFoundError(Exception):
    pass


class DatasetConfigNotFoundError(Exception):
    pass


class DatasetValidationError(Exception):
    pass


class DatasetVersionMismatchError(Exception):
    pass


class DataLoderExecutionError(Exception):
    pass
