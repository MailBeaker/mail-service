from ubuntu:14.04

RUN apt-get -y update && apt-get install -y \
    python-software-properties \
    software-properties-common \
    python3 \
    g++ \
    make \
    python-dev \
    libffi-dev \
    libssl-dev \
    python3-pip \
    git

# Moving mail-service code into directory
RUN mkdir -p /opt/mail-service
ENV PYTHONPATH /opt/mail-service
ADD requirements.txt /opt/mail-service/
RUN pip3 install -r /opt/mail-service/requirements.txt
ADD . /opt/mail-service/

# Adding a celery user
RUN useradd celery -M

# set celery user
USER celery

CMD ["python3", "/usr/local/bin/celery", "worker", "-A", "mail_service.gmail_service.worker", "--loglevel=info"]
