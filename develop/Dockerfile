ARG python_ver=3.12
FROM python:${python_ver}

ARG netbox_ver=v4.5.9
ENV PYTHONUNBUFFERED 1

RUN mkdir -p /opt

RUN pip install --upgrade pip

# -------------------------------------------------------------------------------------
# Install NetBox
# -------------------------------------------------------------------------------------
RUN git clone --single-branch --branch ${netbox_ver} https://github.com/netbox-community/netbox.git /opt/netbox/ && \
    cd /opt/netbox/ && \
    pip install -r /opt/netbox/requirements.txt

RUN pip install tblib

# -------------------------------------------------------------------------------------
# Install Netbox Plugin
# -------------------------------------------------------------------------------------
RUN mkdir -p /source
WORKDIR /source
COPY . /source

RUN pip install -e .

WORKDIR /opt/netbox/netbox/
