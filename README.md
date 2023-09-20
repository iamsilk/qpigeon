# qpigeon

An end-to-end encryption message application. Uses quantum-safe cryptography.

## Setup

```sh
pip install -r ./qpigeon/server/requirements_dev.txt
pip install -r ./qpigeon/server/requirements.txt
```

## Debugging

```sh
flask --app ./qpigeon/server/run.py run
```

## Testing

```sh
pytest
# or, to run a specific test case (for example, test_register)
pytest -k test_register
# optionally, add the '-s' option to be able to see print statements
pytest -k test_register -s
```