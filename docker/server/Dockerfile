FROM python:3.12

# Install dependencies
RUN apt-get -y update && \
    apt-get install -y build-essential git cmake libssl-dev

WORKDIR /opt

# Get liboqs
RUN git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs

# Install liboqs
RUN cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON && \
    cmake --build liboqs/build --parallel 4 && \
    cmake --build liboqs/build --target install

# Get liboqs-python
RUN git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs-python.git

# setup paths for liboqs-python
ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
ENV PYTHONPATH=$PYTHONPATH:/opt/liboqs-python

WORKDIR /app

# copy source code
COPY qpigeon/server ./qpigeon/server
COPY qpigeon/shared ./qpigeon/shared

# install requirements
RUN echo "/opt/liboqs-python" >> qpigeon/server/requirements.txt
RUN pip install --no-cache-dir --upgrade -r qpigeon/server/requirements.txt

ENV FLASK_APP=/app/qpigeon/server

CMD ["python", "-m", "flask", "run", "--host=0.0.0.0"]
