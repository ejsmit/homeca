# HOMECA

Based on https://github.com/jsha/minica, but in python.   Rewrote it because I wanted 
to figure out how to create certificates in python, and because I needed it for my own
network. I have some servers that are not accessible externally, with internal only names,
so Letsencrypt certificates would not workfor them.


## Getting Started

```
conda env create
conda activate homeca
```

## Installing

Get back to system python3 by deactivating conda env, and install using setup script.
```
conda deactivate
sudo python3 setup.py install
```
This should install everything to prefix /usr/local

## Running it

```
homeca
```
Subdirectories will be created below current directory.  A cacert directory will store the 
root ca certificate and passphrase.   This root ca will be reused when running `homeca` again from 
the same folder.   destination certificates will be saved in their own directries, usually using the 
first domain name form the command line as folder name.

I keep my certificates in an encrypted vault on my nextcloud drive. This is fine for the few personal 
certificates I use.

