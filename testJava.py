import jpype
import jpype.imports
from jpype.types import *

"""
jpype.startJVM(
    jpype.getDefaultJVMPath(),
    "-Dsun.security.smartcardio.library=/lib/aarch64-linux-gnu/libpcsclite.so.1",
    "-Djava.class.path=/home/KNX/keystore/src"
)

KeyStore = jpype.JClass("de.hu_berlin.keystore.Keystore")
args = jpype.JArray(jpype.JString)([])
KeyStore.Keystore()
"""
#1. erstelle Keystore
#2. initialize
#3. decryptAndVerify1
#4. Am ende closeCardChannel

encrypted = [0x29,0x00,0xbc,0xd0,0x11,0x02,0x00,0x01,0x0e,0x03,0xf1,0x10,0x00,0x38,0xb8,0x1c,0x0b,0x19,0xce,0x4c,0xdb,0x5a,0x65,0x95]
as_bytes = bytearray(encrypted)

jpype.startJVM(jpype.getDefaultJVMPath(),
                "-Dsun.security.smartcardio.library=/lib/aarch64-linux-gnu/libpcsclite.so.1",
                "-Djava.class.path=/home/KNX/keystore/src")

Keystore = jpype.JClass("de.hu_berlin.keystore.Keystore")
keystore = Keystore()
keystore.initialize()
try:
    decrypted_data = keystore.decryptAndVerify1(as_bytes)
    b = [byte & 0xFF for byte in decrypted_data]
    print(' '.join(f"{byte:02x}" for byte in b))
except jpype.JClass("de.hu_berlin.keystore.KeystoreException") as e:
   print(e.getReason())
    


