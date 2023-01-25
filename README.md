# Siguard

## Installation and setup

It requires Python 3.6-3.9.

```
$ cd Siguard
$ pip install -r requirements.txt
```

## Usage

Run:

```
$ sigu analyze <solidity-file>
```

Or:

```
$ sigu analyze -f <bytecode-file>
```

Specify the maximum number of transaction to explore with `-t `. You can also set a timeout with `--execution-timeout `.

An web service of Siguard is available at http://siguard.xyz .

## Acknowledgement

This project is based on an open-source repository, [Mythril](https://github.com/ConsenSys/mythril). Thanks for their helpful codebase!