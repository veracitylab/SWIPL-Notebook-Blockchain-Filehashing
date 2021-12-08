FROM swipl AS prolog 
RUN apt update -y && apt install -y software-properties-common 
RUN apt-get -y install python3 python3-pip wget
RUN python3 -m pip install --upgrade jswipl jupyterlab notebook iroha
RUN mkdir swi-kernel
RUN cd swi-kernel && wget https://raw.githubusercontent.com/targodan/jupyter-swi-prolog/master/kernel.json
RUN jupyter kernelspec install swi-kernel --user
RUN rmdir --ignore-fail-on-non-empty swi-kernel
ENV DEFAULT_KERNEL_NAME SWI-Prolog
COPY run-notebook /usr/bin/run-notebook
COPY setup /setup
WORKDIR /setup
RUN pip install -r ./requirements.txt
