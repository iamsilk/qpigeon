# qpigeon

An end-to-end encryption message application. Uses quantum-safe cryptography.

## Features

This project is a work-in-progress. Core functionality is still being implemented.

## Setup

Install the requirements.

```sh
python -m pip install -r requirements_dev.txt
```

And also create the qpigeon docker network (this allows the client and server to talk to each other).

```sh
docker network create qpigeon
```

## Testing

```sh
docker build -t qpigeon-tests -f docker/tests/Dockerfile .
docker run -it qpigeon-tests
```

## Debugging

### Server

```sh
docker compose -f docker/server/docker-compose.yaml up --build
```

### Client

```sh
docker compose -f docker/client/docker-compose.yaml build
docker compose -f docker/client/docker-compose.yaml run --rm client
```

## Demo

To demo qpigeon, you will need to setup three terminals:

1. In the first terminal, start the server.
    ```sh
    docker compose -f docker/server/docker-compose.yaml up --build
    ```

2. In the second terminal, start Bob's client.
    ```sh
    $env:QPIGEON_PROFILE='bob' # export QPIGEON_PROFILE=bob
    docker compose -f docker/client/docker-compose.yaml build
    docker compose -f docker/client/docker-compose.yaml run --rm client
    ```

2. In the third terminal, start Alice's client.
    ```sh
    $env:QPIGEON_PROFILE='alice' # export QPIGEON_PROFILE=alice
    docker compose -f docker/client/docker-compose.yaml build
    docker compose -f docker/client/docker-compose.yaml run --rm client
    ```