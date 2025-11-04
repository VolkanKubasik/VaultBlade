#!/usr/bin/env python3
import argparse, base64, hashlib, hmac as hmaclib, json, os
from dataclasses import dataclass, asdict
from typing import Literal, List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, XChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization, hashes as c_hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from argon2.low_level import hash_secret_raw, Type as Argon2Type
from argon2 import PasswordHasher

VERSION = "1.0.0"
MAGIC = "VBLD"

def read_all_binary(path):
    with open(path, "rb") as f:
        return f.read()

def write_all_binary(path, data):
    with open(path, "wb") as f:
        f.write(data)

def b64e(b):
    return base64.b64encode(b).decode()

def b64d(s):
    return base64.b64decode(s.encode())

def stream_sha256(path, bufsize=1048576):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(bufsize)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def hash_bytes(algo, data):
    if algo == "sha256":
        return hashlib.sha256(data).hexdigest()
    if algo == "sha3-256":
        return hashlib.sha3_256(data).hexdigest()
    if algo == "blake2b":
        return hashlib.blake2b(data).hexdigest()

def pw_hash(password, scheme):
    pwd = password.encode()
    if scheme == "argon2id":
        ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1)
        return ph.hash(password)
    salt = os.urandom(16)
    if scheme == "scrypt":
        kdf = Scrypt(salt=salt, length=32, n=32768, r=8, p=1)
        key = kdf.derive(pwd)
        obj = {"scheme": "scrypt","n":32768,"r":8,"p":1,"salt":b64e(salt),"hash":b64e(key)}
        return "scrypt$"+base64.urlsafe_b64encode(json.dumps(obj).encode()).decode()
    if scheme == "pbkdf2":
        kdf = PBKDF2HMAC(algorithm=c_hashes.SHA256(), length=32, salt=salt, iterations=310000)
        key = kdf.derive(pwd)
        obj = {"scheme":"pbkdf2","iter":310000,"salt":b64e(salt),"hash":b64e(key)}
        return "pbkdf2$"+base64.urlsafe_b64encode(json.dumps(obj).encode()).decode()

def pw_verify(password, encoded):
    if encoded.startswith("$argon2"):
        ph = PasswordHasher()
        try:
            ph.verify(encoded, password)
            return True
        except:
            return False
    if encoded.startswith("scrypt$") or encoded.startswith("pbkdf2$"):
        try:
            blob = base64.urlsafe_b64decode(encoded.split("$",1)[1].encode())
            obj = json.loads(blob.decode())
            salt = b64d(obj["salt"])
            stored = b64d(obj["hash"])
            pwd = password.encode()
            if obj["scheme"]=="scrypt":
                kdf = Scrypt(salt=salt,length=32,n=obj["n"],r=obj["r"],p=obj["p"])
                try:
                    kdf.verify(pwd,stored)
                    return True
                except:
                    return False
            if obj["scheme"]=="pbkdf2":
                kdf = PBKDF2HMAC(algorithm=c_hashes.SHA256(),length=32,salt=salt,iterations=obj["iter"])
                try:
                    kdf.verify(pwd,stored)
                    return True
                except:
                    return False
        except:
            return False
    return False

@dataclass
class KDFSpec:
    name: str
    salt_b64: str
    params: dict

@dataclass
class EncHeader:
    magic: str
    version: str
    aead: str
    kdf: KDFSpec
    nonce_b64: str
    aad: str|None

def kdf_to_key(password, spec):
    pwd = password.encode()
    salt = b64d(spec.salt_b64)
    if spec.name=="argon2id":
        t=spec.params.get("t",3)
        m=spec.params.get("m",65536)
        p=spec.params.get("p",1)
        return hash_secret_raw(secret=pwd,salt=salt,time_cost=t,memory_cost=m,parallelism=p,hash_len=32,type=Argon2Type.ID)
    if spec.name=="scrypt":
        kdf=Scrypt(salt=salt,length=32,n=spec.params.get("n",32768),r=spec.params.get("r",8),p=spec.params.get("p",1))
        return kdf.derive(pwd)
    if spec.name=="pbkdf2":
        it=spec.params.get("iter",310000)
        kdf=PBKDF2HMAC(algorithm=c_hashes.SHA256(),length=32,salt=salt,iterations=it)
        return kdf.derive(pwd)

def encrypt_file(infile,outfile,password,aead="xchacha20",kdf_name="argon2id",aad=None):
    pt = read_all_binary(infile)
    kdf_spec = KDFSpec(name=kdf_name,salt_b64=b64e(os.urandom(16)),params={"t":3,"m":65536,"p":1,"iter":310000,"n":32768,"r":8})
    key = kdf_to_key(password,kdf_spec)
    if aead=="xchacha20":
        nonce=os.urandom(24)
        boxer=XChaCha20Poly1305(key)
    else:
        nonce=os.urandom(12)
        boxer=AESGCM(key)
    aad_bytes=aad.encode() if aad else None
    ct=boxer.encrypt(nonce,pt,aad_bytes)
    header=EncHeader(magic=MAGIC,version=VERSION,aead=aead,kdf=kdf_spec,nonce_b64=b64e(nonce),aad=aad)
    blob={"header":asdict(header),"ct":b64e(ct)}
    write_all_binary(outfile,json.dumps(blob).encode())

def decrypt_file(infile,outfile,password):
    data=json.loads(read_all_binary(infile).decode())
    header=data["header"]
    kdf_obj=KDFSpec(name=header["kdf"]["name"],salt_b64=header["kdf"]["salt_b64"],params=header["kdf"]["params"])
    key=kdf_to_key(password,kdf_obj)
    ct=b64d(data["ct"])
    nonce=b64d(header["nonce_b64"])
    aad=header.get("aad")
    aad_bytes=aad.encode() if aad else None
    if header["aead"]=="xchacha20":
        boxer=XChaCha20Poly1305(key)
    else:
        boxer=AESGCM(key)
    pt=boxer.decrypt(nonce,ct,aad_bytes)
    write_all_binary(outfile,pt)

def hmac_sha256_hex(key,data):
    return hmaclib.new(key,data,digestmod=hashlib.sha256).hexdigest()

def ed25519_keygen(priv_out,pub_out):
    priv=Ed25519PrivateKey.generate()
    pub=priv.public_key()
    write_all_binary(priv_out,priv.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption()))
    write_all_binary(pub_out,pub.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo))

def ed25519_sign(priv_pem,infile,sig_out):
    priv=serialization.load_pem_private_key(read_all_binary(priv_pem),password=None)
    sig=priv.sign(read_all_binary(infile))
    write_all_binary(sig_out,sig)

def ed25519_verify(pub_pem,infile,sig_path):
    pub=serialization.load_pem_public_key(read_all_binary(pub_pem))
    try:
        pub.verify(read_all_binary(sig_path),read_all_binary(infile))
        return True
    except:
        return False

def merkle_root(paths):
    leaves=[bytes.fromhex(stream_sha256(p)) for p in paths]
    if not leaves:
        raise ValueError("no files")
    layer=leaves
    while len(layer)>1:
        nxt=[]
        for i in range(0,len(layer),2):
            left=layer[i]
            right=layer[i if i+1>=len(layer) else i+1]
            nxt.append(hashlib.sha256(left+right).digest())
        layer=nxt
    return layer[0].hex()

def cli():
    p=argparse.ArgumentParser()
    p.add_argument("--version",action="version",version=VERSION)
    sub=p.add_subparsers(dest="cmd",required=True)
    h=sub.add_parser("hash");h.add_argument("--algo",choices=["sha256","sha3-256","blake2b"],default="sha256");g=h.add_mutually_exclusive_group(required=True);g.add_argument("--text");g.add_argument("--file")
    hm=sub.add_parser("hmac");hm.add_argument("--key",required=True);g2=hm.add_mutually_exclusive_group(required=True);g2.add_argument("--text");g2.add_argument("--file")
    ph=sub.add_parser("pw-hash");ph.add_argument("--scheme",choices=["argon2id","scrypt","pbkdf2"],default="argon2id");ph.add_argument("password")
    pv=sub.add_parser("pw-verify");pv.add_argument("password");pv.add_argument("encoded")
    enc=sub.add_parser("enc");enc.add_argument("--in",dest="infile",required=True);enc.add_argument("--out",dest="outfile",required=True);enc.add_argument("--password",required=True);enc.add_argument("--aead",choices=["xchacha20","aesgcm"],default="xchacha20");enc.add_argument("--kdf",choices=["argon2id","scrypt","pbkdf2"],default="argon2id");enc.add_argument("--aad")
    dec=sub.add_parser("dec");dec.add_argument("--in",dest="infile",required=True);dec.add_argument("--out",dest="outfile",required=True);dec.add_argument("--password",required=True)
    kg=sub.add_parser("keygen");kg.add_argument("--priv",required=True);kg.add_argument("--pub",required=True)
    sg=sub.add_parser("sign");sg.add_argument("--priv",required=True);sg.add_argument("--in",dest="infile",required=True);sg.add_argument("--sig",required=True)
    vf=sub.add_parser("verify");vf.add_argument("--pub",required=True);vf.add_argument("--in",dest="infile",required=True);vf.add_argument("--sig",required=True)
    mk=sub.add_parser("merkle");mk.add_argument("files",nargs="+")
    return p.parse_args()

def main():
    a=cli()
    if a.cmd=="hash":
        print(hash_bytes(a.algo,a.text.encode()) if a.text else stream_sha256(a.file));return
    if a.cmd=="hmac":
        data=a.text.encode() if a.text else read_all_binary(a.file);print(hmac_sha256_hex(a.key.encode(),data));return
    if a.cmd=="pw-hash":
        print(pw_hash(a.password,a.scheme));return
    if a.cmd=="pw-verify":
        print("OK" if pw_verify(a.password,a.encoded) else "FAIL");return
    if a.cmd=="enc":
        encrypt_file(a.infile,a.outfile,a.password,a.aead,a.kdf,a.aad);print("Encrypted");return
    if a.cmd=="dec":
        decrypt_file(a.infile,a.outfile,a.password);print("Decrypted");return
    if a.cmd=="keygen":
        ed25519_keygen(a.priv,a.pub);print("Keypair generated");return
    if a.cmd=="sign":
        ed25519_sign(a.priv,a.infile,a.sig);print("Signed");return
    if a.cmd=="verify":
        print("OK" if ed25519_verify(a.pub,a.infile,a.sig) else "FAIL");return
    if a.cmd=="merkle":
        print(merkle_root(a.files));return

if __name__=="__main__":
    main()
