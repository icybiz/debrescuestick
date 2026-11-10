"""Validate and normalize one OpenSSH public key; never accept authorized_keys options."""
import base64
import binascii
import hashlib
import struct


class InvalidKey(ValueError):
    pass


def public_key(value):
    if not isinstance(value,str) or len(value)>16384:
        raise InvalidKey('Bitte einen öffentlichen SSH-Schlüssel angeben.')
    value=value.strip()
    if '\n' in value or '\r' in value or 'PRIVATE KEY' in value:
        raise InvalidKey('Bitte nur eine öffentliche Schlüsselzeile einfügen, keinen privaten Schlüssel.')
    parts=value.split(maxsplit=2)
    if len(parts)<2:raise InvalidKey('Das ist kein öffentlicher OpenSSH-Schlüssel.')
    kind,encoded=parts[:2]
    supported={'ssh-ed25519','ssh-rsa','ecdsa-sha2-nistp256','ecdsa-sha2-nistp384','ecdsa-sha2-nistp521',
               'sk-ssh-ed25519@openssh.com','sk-ecdsa-sha2-nistp256@openssh.com'}
    if kind not in supported:
        raise InvalidKey('Unterstützt werden Ed25519, RSA ab2048Bit, ECDSA und OpenSSH-Sicherheitsschlüssel.')
    try:raw=base64.b64decode(encoded,validate=True)
    except (ValueError,binascii.Error) as error:raise InvalidKey('Ungültige Base64-Schlüsseldaten.') from error
    if len(raw)>8192:raise InvalidKey('Der Schlüssel ist zu groß.')
    position=0
    def field():
        nonlocal position
        if position+4>len(raw):raise InvalidKey('Unvollständiger Schlüssel.')
        size=struct.unpack('>I',raw[position:position+4])[0];position+=4
        if size>len(raw)-position:raise InvalidKey('Unvollständige Schlüsseldaten.')
        result=raw[position:position+size];position+=size;return result
    if field()!=kind.encode():raise InvalidKey('Schlüsseltyp und Schlüsseldaten passen nicht zusammen.')
    if kind in ('ssh-ed25519','sk-ssh-ed25519@openssh.com'):
        if len(field())!=32:raise InvalidKey('Ed25519 benötigt32Bytes Schlüsseldaten.')
    elif kind=='ssh-rsa':
        exponent,modulus=field(),field()
        if not exponent or not modulus or exponent[0]&128 or modulus[0]&128:
            raise InvalidKey('Ungültiger RSA-Schlüssel.')
        e=int.from_bytes(exponent);n=int.from_bytes(modulus)
        if e<3 or e%2==0 or n.bit_length()<2048 or n.bit_length()>16384 or n%2==0:
            raise InvalidKey('RSA benötigt einen gültigen Schlüssel mit mindestens2048Bit.')
    else:
        curve=kind.removeprefix('sk-').split('-')[-1].split('@')[0]
        if field()!=curve.encode():raise InvalidKey('ECDSA-Kurve und Schlüsseltyp passen nicht zusammen.')
        point=field();width={'nistp256':32,'nistp384':48,'nistp521':66}[curve]
        if len(point)!=1+2*width or point[0]!=4:raise InvalidKey('Ungültiger ECDSA-Punkt.')
    if kind.startswith('sk-'):
        application=field()
        if not application or len(application)>1024:raise InvalidKey('Ungültige Sicherheitsschlüssel-Anwendung.')
    if position!=len(raw):raise InvalidKey('Unerwartete zusätzliche Schlüsseldaten.')
    normalized=kind+' '+base64.b64encode(raw).decode()+'\n'
    fingerprint='SHA256:'+base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip('=')
    return normalized,fingerprint
