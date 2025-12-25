from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable


def recurse_json(contents: str, fnc: Callable) -> tuple[str, bool]:
    """Recurse with a callback function in JSON objects.

    Converts contents str into dict. This function is a wrapper for recurse_dict.

    Args:
        contents:
            JSON contents string
        fnc:
            Callback function for recursion.
            This function must return a tuple of (val, modified)
            where modified is Boolean
        depth:
            Recursion depth limit to prevent self reference

    Returns:
        new_contents:
            New JSON contents string
        modified:
            Whether it is modified or not while recursive localization
    """

    def recurse_dict(
        d, fnc, d_parent=None, d_parent_key=None, lst=None, lst_idx=None, modified=False
    ):
        """Recurse dict with a callback function.

        This function modifies mutable d.
        """
        if isinstance(d, dict):
            for k, v in d.items():
                modified |= recurse_dict(v, fnc, d_parent=d, d_parent_key=k, modified=modified)
        elif isinstance(d, list):
            for i, v in enumerate(d):
                modified |= recurse_dict(v, fnc, lst=d, lst_idx=i, modified=modified)
        elif isinstance(d, str):
            assert d_parent is not None or lst is not None
            new_val, modified_ = fnc(d)
            modified |= modified_

            if modified_:
                if d_parent is not None:
                    d_parent[d_parent_key] = new_val
                elif lst is not None:
                    lst[lst_idx] = new_val
                else:
                    msg = "Recursion failed."
                    raise ValueError(msg)
        return modified

    d = json.loads(contents)
    # d is modified inside of recurse_dict
    modified = recurse_dict(d, fnc)

    return json.dumps(d, indent=4), modified


def recurse_tsv(contents: str, fnc: Callable, delim: str = "\t") -> tuple[str, bool]:
    """Recurse with a callback function in TSV contents.

    Just visit each line and look at values only.

    Args:
        contents:
            TSV/CSV contents string
        fnc:
            Callback function for recursion.
            This function must return a tuple of (val, modified)
            where modified is Boolean
    Returns:
        new_contents:
            New TSV/CSV contents string
        modified:
            Whether it is modified or not while recursive localization
    """
    modified = False
    new_contents = []
    for line in contents.split("\n"):
        new_values = []
        for v in line.split(delim):
            new_val, modified_ = fnc(v)
            modified |= modified_
            if modified_:
                new_values.append(new_val)
            else:
                new_values.append(v)
        new_contents.append(delim.join(new_values))

    return "\n".join(new_contents), modified


def recurse_csv(contents: str, fnc: Callable, delim: str = ",") -> tuple[str, bool]:
    """Same as recurse_tsv but with delimiter ','."""
    return recurse_tsv(contents, fnc, delim=delim)
