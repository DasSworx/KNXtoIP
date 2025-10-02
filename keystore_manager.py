import jpype
import jpype.imports

jvm_started = False
keystore = None

def ensure_jvm_up():
    global jvm_started
    if not jvm_started:
        jpype.startJVM(jpype.getDefaultJVMPath(),
                "-Dsun.security.smartcardio.library=/lib/aarch64-linux-gnu/libpcsclite.so.1",
                "-Djava.class.path=/home/KNX/keystore/src")
        jvm_started = True
    return jpype.isJVMStarted()

def get_keystore():
    global keystore
    if keystore is None:
        ensure_jvm_up()
        Keystore = jpype.JClass("de.hu_berlin.keystore.Keystore")
        keystore = Keystore()
        keystore.initialize()
    return keystore

def get_exception():
    ensure_jvm_up()
    return jpype.JClass("de.hu_berlin.keystore.KeystoreException")