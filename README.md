# qpigeon

An end-to-end encryption message application. Uses quantum-safe cryptography.

## Features

This project is a work-in-progress. Core functionality is still being implemented.

### Server

- [x] Registering accounts.
- [x] Login to accounts.
- [ ] Change signature of account.
- [x] Add and remove contacts.
- [ ] Send and receive messages.

### Console Client

- [ ] Registering accounts.
- [ ] Login to accounts.
- [ ] Change signature of account.
- [ ] Add and remove contacts.
- [ ] Send and receive messages.

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