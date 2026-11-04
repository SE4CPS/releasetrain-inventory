# Contributing

## Ground rules

* Source lives under `src/releasetrain_inventory/`. Keep pull requests
  focused on one change.
* Run the test suite before opening a pull request.

## Local development

```bash
pip install -e .          # editable install, picks up source edits immediately
python -m pyflakes src/releasetrain_inventory/*.py
```

## Tests

```bash
python -m unittest discover -s tests
```

## Commit messages

Short imperative subject, then a body explaining why. Reference issues where
relevant.
