FROM python:3

RUN apt-get update && apt-get install -y libmemcached-dev

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# COPY . .

CMD [ "/bin/bash" ]
