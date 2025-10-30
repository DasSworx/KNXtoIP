import jpype
import util.util_config as u

keystore = None

def ensure_jvm_up():
    if not jpype.isJVMStarted():
        jpype.startJVM(jpype.getDefaultJVMPath(),
                "-Dsun.security.smartcardio.library=/lib/aarch64-linux-gnu/libpcsclite.so.1",
                u.assemble_java_path_for_jpype())
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