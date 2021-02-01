FROM ubuntu:20.04
ENV PROJECT_ROOT /suit
WORKDIR ${PROJECT_ROOT}
RUN apt-get -y update
RUN apt-get -y upgrade
RUN apt-get -y install python srecord gcc-arm-none-eabi make python3-pip
RUN pip3 install mbed-cli cryptography colorama cbor pyyaml jsonschema \
    mbed_cloud_sdk jinja2 mbed_ls mbed_host_tests mbed_greentea pyelftools \
    manifest_tool icetea pycryptodome pyusb cmsis_pack_manager psutil click
