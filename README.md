### Equihash CPU&GPU Miner container based on Ubuntu 14.04

Miner for Nicehash pool (Build CPU_XENONCAT).

## Usage:

Clone

```
git clone https://github.com/rhamdeew/nheqminer-container
```

*edit Dockerfile, change pool and BTC wallet*


Build
```
docker build -t rhamdeew/nheqminer .
```
and run

```
docker run --rm rhamdeew/nheqminer
```
*Fast, but cannot stopped with Ctrl+С. Highly recommended for run in tmux/screen*

or

```
docker run --d rhamdeew/nheqminer
```
*Not recommended - run slow, need remove used containers*

## Options

You can limit container cpu usage with standart Docker options - **cpuset-cpus** and **cpu-shares**

**Example:**

Limit cpu cores

```
docker run --cpuset-cpus="0" -d rhamdeew/nicehash
```

Limit cpu share with other containers

```
docker run --cpu-shares=512 -d rhamdeew/nicehash
```
