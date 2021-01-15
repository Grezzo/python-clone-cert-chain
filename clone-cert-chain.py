#!/usr/bin/env python3

from random import randint
from sys import argv
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat)


def clone_cert(original, pub_key, signing_key, serial=False):
    """
    Clone a certificate using:
      original: An x509 certificate to clone
      pub_key:  A public key to embed in the certificate
      priv_key: A private key to sign the certificate with
                - In the case of root CA, this is the private key that
                  corresponds to the public key
                - In other cases, it the the private key of the CA one level up
      serial:   Serial number to use. Cloned serial no will be used, if omitted
    """
    builder = (
            x509.CertificateBuilder()
            .subject_name(original.subject)
            .issuer_name(original.issuer)
            .not_valid_before(original.not_valid_before)
            .not_valid_after(original.not_valid_after)
            .public_key(pub_key))
    if serial:
        builder = builder.serial_number(serial)
        print(f'Used Supplied Serial Number: {serial}')
    else:
        builder = builder.serial_number(original.serial_number)
        print('Cloned Serial Number')
    for extension in original.extensions:
        # Cloning Signed Certificate Timestamps (used in the certificate
        # transparecy flow causes errors when signing, so don't clone that
        # extension
        if (
            type(extension.value) ==
            x509.extensions.PrecertificateSignedCertificateTimestamps
        ):
            print('Skipping SignatureTimestamps')
            continue
        builder = builder.add_extension(extension.value, extension.critical)
    cert = builder.sign(signing_key, hashes.SHA256(), default_backend())
    return cert


def load_chain(pem_file):
    # Load individual certificates from a chain in a pem file
    with open(pem_file, 'rb') as infile:
        pems_chain_lines = infile.read().splitlines()
    # Split lines into groups of 3 lines (each pem in the chain is 3 lines)
    pems_lines = [pems_chain_lines[i:i + 3] for i in range(
        0, len(pems_chain_lines), 3)]
    # Re-join 3 lines while wrapping the second line at 64 characters, as
    # required by cryptography module, then add to new pem array
    pems = []
    for pem_lines in pems_lines:
        pem = b'\r\n'.join(
                [pem_lines[0]] +
                [pem_lines[1][i:i+64] for i in range(
                    0, len(pem_lines[1]), 64)] +
                [pem_lines[2]]) + b'\r\n'
        pems.append(pem)
    return pems


def clone_chain(pem_file, cloned_pem_file):
    pems = load_chain(pem_file)
    print(f'Loaded {len(pems)} Certificates from {pem_file}')
    clones = []
    # Reversed so we get the root certificate first
    for index, pem in enumerate(reversed(pems)):
        print(f'Cloning Certificate {index+1}...')
        cert = x509.load_pem_x509_certificate(pem, default_backend())
        print(f'Subject: {cert.subject.rfc4514_string()}')
        key_size = 2048
        priv_key = rsa.generate_private_key(65537, key_size, default_backend())
        pub_key = priv_key.public_key()
        if index != len(pems) - 1:
            serial = randint(0, 255**16)
        else:
            serial = False
        if index == 0:
            print(
                'Setting own private key as signing key '
                '(self-signing Root CA)')
            signing_key = priv_key
        clones.append(clone_cert(cert, pub_key, signing_key, serial))
        print(f'Cloned Certificate {index+1}')
        signing_key = priv_key
    print(f'Cloned all {len(pems)} Certificates')

    with open(cloned_pem_file, 'wb') as outfile:
        outfile.write(priv_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        # Reversed because the server must be at the top and root CA at the bottom
        for clone in reversed(clones):
            outfile.write(clone.public_bytes(Encoding.PEM))
    print(f'Written {cloned_pem_file} file')


if __name__ == "__main__":
    clone_chain(sys.argv[1], sys.argv[2])
