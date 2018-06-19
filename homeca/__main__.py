#!/usr/bin/env python

import sys
import datetime
import os
import argparse
import ipaddress

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography import x509


CA_CERT_PATH = "cacert"
CA_KEY = "ca.key.pem"
CA_CERT = "ca.cert.pem"
CA_CERT_CRT = "root_ca_cert.crt"



def load_root_ca(ca_name):
    print("==> Loading Root CA")

    if not os.path.exists(CA_CERT_PATH):
        os.mkdir(CA_CERT_PATH)

    # just check for key.  For now assume cert exists if key does.    
    if not os.path.exists(CA_CERT_PATH+ '/' + CA_KEY):
        print("==> not found - creating it")
        key = create_rsa_key(CA_CERT_PATH + '/' + CA_KEY)
        cert = create_root_ca_cert(
            CA_CERT_PATH + '/' + CA_CERT, 
            key, 
            ca_name)
    else:
        with open(CA_CERT_PATH + '/' + CA_KEY, "rb") as key_file:
            key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        with open(CA_CERT_PATH + '/' + CA_CERT, "rb") as cert_file:
            cert = x509.load_pem_x509_certificate(
                cert_file.read(), 
                backend=default_backend()
            )
    print('...    Issuer: ' + cert.issuer.get_attributes_for_oid(x509.OID_COMMON_NAME)[0].value)
    return (cert,key)



def create_rsa_key(path):

    print("...    Creating private key")
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    return key   



def create_root_ca_cert(path, key, name):
    print("...    Creating Root CA Certificate")
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, name),
    ])

    cert = ( 
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650)) 
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=False,encipher_only=False, decipher_only=False),  critical=True) 
        .add_extension(x509.ExtendedKeyUsage(
            [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH] ),
            critical=True)
        .sign(key, hashes.SHA256(), default_backend())
    )
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert


def create_server_certificates(domains, ips, issuer_cert, issuer_key):
    print("==> Creating Server certificate")
    
    if len(domains)>0:
        cn = domains[0]
    else:
        cn=ips[0]
    
    if os.path.exists(cn):
        print("\nError:  Directory for CN='%s' already exists" % cn )
        return

    os.mkdir(cn)
    key_name = cn + '/' + cn + '.key.pem'
    cert_name = cn + '/' + cn + '.cert.pem'

    key = create_rsa_key(key_name)

    print("...    Creating server certificate")
    print("...    CN=%s" % cn)
    subject = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, cn),
    ])
    servers = [x509.DNSName(name) for name in domains]
    servers += [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ips]

    builder = ( 
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650)) 
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False,encipher_only=False, decipher_only=False),  critical=True) 
        .add_extension(x509.ExtendedKeyUsage(
            [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH] ),
            critical=True)
        .add_extension(x509.SubjectAlternativeName(servers), critical=False)
    )

    print("...    Signing certificate")
    cert = builder.sign(issuer_key, hashes.SHA256(), default_backend() )
    with open(cert_name, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))




def main(args=None): 

    if args is None:
        args = sys.argv[1:]
    
    parser = argparse.ArgumentParser(description='Create x509 certificates for my home network.')
    parser.add_argument('--name', 
                        help='Issuer name for root ca certificate')
    parser.add_argument('--domain', 
                        help='comma separated list of domains')
    parser.add_argument('--ip', 
                        help='Comma separated list of ip addresses')
    args = parser.parse_args()


    if not args.domain and not args.ip:
        parser.print_help()
        exit(1)
    
    ca_name = "Rassie Smit Root CA"
    if args.name:
        ca_name = args.name

    domain_names = args.domain.split(',') if args.domain else []
    ip_addresses = args.ip.split(',') if args.ip else []


    # load root certs (or create it if it does not exist)
    (ca_cert, ca_key) = load_root_ca(ca_name)

    # now go and create certificate
    create_server_certificates(domain_names, ip_addresses, ca_cert, ca_key)



if __name__ == "__main__":
    main()
