FROM ubuntu:14.04

RUN apt-get update \
	&& apt-get install -y cmake build-essential libboost-all-dev git \
	&& cd /root/ \
	&& git clone -b Linux https://github.com/nicehash/nheqminer.git \
	&& cd nheqminer/cpu_xenoncat/Linux/asm/ \
	&& sh assemble.sh \
	&& cd ../../../Linux_cmake/nheqminer_cpu_xenoncat \
	&& cmake . \
	&& make -j $(nproc)

CMD /root/nheqminer/Linux_cmake/nheqminer_cpu_xenoncat/nheqminer_cpu_xenoncat -l equihash.eu.nicehash.com:3357 -u 1C6bQG1HVkP8xuo5nTkSuvWyPPkryjEYCN.worker1 -t `nproc`