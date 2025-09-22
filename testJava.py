import jpype
import jpype.imports
from jpype.types import *


jpype.startJVM(
    jpype.getDefaultJVMPath(),
    "-Dsun.security.smartcardio.library=/lib/aarch64-linux-gnu/libpcsclite.so.1",
    "-Djava.class.path=/home/KNX/keystore/src/"
)

KeyStoreTest = jpype.JClass("KeystoreTest")
args = jpype.JArray(jpype.JString)([])
KeyStoreTest.main(args)