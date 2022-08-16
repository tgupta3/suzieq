from typing import Callable, Dict, List, Tuple
import pandas as pd
import pytest
import yaml
from suzieq.sqobjects import get_sqobject, get_tables
from suzieq.sqobjects.basicobj import SqObject
from ..conftest import create_dummy_config_file


_COMMANDS_FILE = 'commands.yml'


@pytest.mark.sqobject
def test_sqobject_columns():
    """Test that the columns returned are correct.

    This check is performed both on empty and non-empty dataframes
    """
    with open(_COMMANDS_FILE, 'r') as fp:
        table_cmds = yaml.safe_load(fp)
    common_functions: Dict = table_cmds['all']
    cfg_file = create_dummy_config_file()
    for table in get_tables():
        sqobj: SqObject = get_sqobject(table)(config_file=cfg_file)
        table_functions: Dict[str, List[Dict]] = common_functions.copy()
        table_functions.update(table_cmds.get(table, {}))
        for fun, args in table_functions.items():
            if args and args[0] and 'skip' in args[0]:
                # skip means not to run the test
                continue
            compare_results(sqobj, fun, args or [])


def get_exp_cols(sqobj: SqObject, df: pd.DataFrame, fun_args: Dict, fun: str) \
        -> List[str]:
    """Return the set of columns expected by the sqobject

    Returns:
        List[str]: expected columns
    """
    if fun == 'get':
        exp_cols = sqobj.schema.get_display_fields(
            fun_args.get('columns', ['default']))
        schema = sqobj.schema.get_raw_schema()
        drop_cols = [item['name']
                     for item in schema if item.get('suppress', False)]
        exp_cols = [c for c in exp_cols if c not in drop_cols]
    elif fun == 'unique':
        exp_cols = fun_args.get('columns', sqobj._unique_def_column)
        if 'count' in fun_args:
            exp_cols.append('numRows')
    elif fun == 'summarize':
        exp_cols = []
    else:
        exp_cols = list(df.columns)
    return exp_cols


def compare_results(sqobj: SqObject, fun: str, fun_args_list: List[Dict]):
    """Execute the function on the sqobject using the args in the fun_args_list
    Then execute the same command adding another argument to receive an
    empty dataframe as result.

    This function checks (for both empty and non empty results):
    - the list of columns is correct
    - the dataframe is not-empty (or empty)
    - if an exception was raised
    - if an error is returned

    Args:
        sqobj (SqObject): sqobject to test
        fun (str): name of the function to test
        fun_args_list (List[Dict]): list of function arguments to test
    """
    table = sqobj.table
    sq_fun = getattr(sqobj, fun)
    for i, fun_args in enumerate(fun_args_list):
        fun_args = fun_args or {}
        non_empty_res, non_empty_exc = run_function(sq_fun, **fun_args)
        if non_empty_exc:
            pytest.fail(f'{table}.{sq_fun.__name__}({i}) exception '
                        f'(non-empty): {non_empty_exc}')
        fun_args.pop('hostname', None)
        empty_res, empty_exc = run_function(
            sq_fun, **fun_args, hostname=['invalid'])
        if empty_exc:
            pytest.fail(f'{table}.{sq_fun.__name__}({i}) exception (empty): '
                        f'{empty_exc}')
        if empty_exc or non_empty_exc:
            continue
        exp_cols = get_exp_cols(sqobj, non_empty_res, fun_args, fun)
        non_empty_cols = list(non_empty_res.columns)
        empty_cols = list(empty_res.columns)
        if 'error' in empty_res.columns and len(empty_res.columns) == 1:
            pytest.fail(f'{table}.{sq_fun.__name__}({i}) error (empty): '
                        f'{empty_res["error"]}')
        elif ('error' in non_empty_res.columns and
              len(non_empty_res.columns) == 1):
            pytest.fail(f'{table}.{sq_fun.__name__}({i}) error (non-empty): '
                        f'{non_empty_res["error"]}')
        elif not empty_res.empty:
            pytest.fail(f'{table}.{sq_fun.__name__}({i}) was not empty')
        elif non_empty_res.empty:
            pytest.fail(f'{table}.{sq_fun.__name__}({i}) was empty')
        elif non_empty_cols != exp_cols:
            pytest.fail(f'{table}.{sq_fun.__name__}({i}) (non-empty) got '
                        f'{non_empty_cols}, expected {exp_cols}')
        elif empty_cols != exp_cols:
            pytest.fail(f'{table}.{sq_fun.__name__}({i}) (empty) got '
                        f'{empty_cols}, expected {exp_cols}')


def run_function(sq_fun: Callable, **kwargs) -> Tuple[pd.DataFrame, Exception]:
    """Executed the function

    Args:
        sq_fun (Callable): function to execute

    Returns:
        Tuple[pd.DataFrame, Exception]: returns the dataframe (or None if an
        exception occurred) and the exception (or None if no exception is
        captured)
    """
    df: pd.DataFrame = None
    exc: Exception = None
    try:
        df = sq_fun(**kwargs)
    except Exception as e:
        exc = e
    return (df, exc)
