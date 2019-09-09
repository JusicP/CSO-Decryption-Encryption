#include <iostream>
#include <Windows.h>
#include <Shlwapi.h>

#define CLOSE_TIME 5000

int key[4]
{
	0x4C7ADF03,
	0x5F30E75F,
	0x1D149820,
	0x3985ADF,
};

void DecryptCSO(int* v, int sz)
{
	int count = sz / 4;
	int unk = 0;
	for (int i = 0; i < count; i += 2)
	{
		int v0 = v[i];
		int v1 = v[i + 1];
		int sum = 84941944608;
		int delta = 0x9e3779b9;

		// расшифровуем 8 байт
		for (int i = 0; i < 32; i++)
		{
			v1 -= ((v0 << 4) - 0x1D149820) ^ (v0 + sum) ^ ((v0 >> 5) - 0x3985ADF);
			unk = sum + v1;
			sum -= delta;
			v0 -= ((v1 << 4) - 0x4C7ADF03) ^ unk ^ ((v1 >> 5) + 0x5F30E75F);
		}

		// фиксируем изменения
		v[i] = v0;
		v[i + 1] = v1;

		// фиксируем обратно магическое число (228)
		sum = 84941944608;
	} 	// и па некселю делаем по кругу
}

void EncryptCSO(int* v, int sz)
{
	int count = sz / 4;
	int unk228 = 0;
	for (int i = 0; i < count; i += 2)
	{
		int v0 = v[i];
		int v1 = v[i + 1];
		int sum = 0;
		int delta = 0x9e3779b9;

		// зашифровуем 8 байт
		for (int i = 0; i < 32; i++)
		{
			sum += delta;
			unk228 = sum + v1;
			v0 += ((v1 << 4) - key[0]) ^ unk228 ^ ((v1 >> 5) + key[1]);
			v1 += ((v0 << 4) - key[2]) ^ (v0 + sum) ^ ((v0 >> 5) - key[3]);
		}

		// фиксируем изменения
		v[i] = v0;
		v[i + 1] = v1;

		// фиксируем обратно магическое число
		sum = 0;
	} 	// и па некселю делаем по кругу
}


void PrintUsage(int argc, char* argv[])
{
	printf("Use -file <\"file\"> and -enc or -dec parameter. Command line:\n");
	for (int i = 0; i < argc; i++)
	{
		printf("%s\n", argv[i]);
	}
	printf("Quiting...\n");
}

int main(int argc, char *argv[])
{
	char inputFilePath[MAX_PATH];
	char outputFilePath[MAX_PATH];
	bool encrypt;

	HFILE hFile;
	HFILE newFile;
	OFSTRUCT tOfStr;
	BY_HANDLE_FILE_INFORMATION bhFileInformation;
	DWORD bytesRead;
	DWORD bytesWritten;
	BYTE *readBuf;

	if (argc < 4)
	{
		PrintUsage(argc, argv);

		Sleep(CLOSE_TIME);
		return 0;
	}

	if (!strcmp(argv[1], "-file"))
	{
		strncpy(inputFilePath, argv[2], sizeof(inputFilePath));
	}
	else
	{
		PrintUsage(argc, argv);

		Sleep(CLOSE_TIME);
		return 0;
	}

	if (!strcmp(argv[3], "-enc"))
	{
		encrypt = true;
	}
	else if (!strcmp(argv[3], "-dec"))
	{
		encrypt = false;
	}
	else
	{
		PrintUsage(argc, argv);

		Sleep(CLOSE_TIME);
		return 0;
	}

	hFile = OpenFile(inputFilePath, &tOfStr, OF_READWRITE);
	if (hFile == HFILE_ERROR)
	{       
		CloseHandle((HANDLE)hFile);

		printf("OpenFile() failed: %d. Make sure that you entered currect file path. Quiting...\n", GetLastError());

		Sleep(CLOSE_TIME);
		return 0;
	}

	GetFileInformationByHandle((HANDLE)hFile, &bhFileInformation);

	int viSize = bhFileInformation.nFileSizeLow;
	readBuf = new BYTE[viSize];
	if (_llseek(hFile, 0 * sizeof(int), 0) != (long)(0 * sizeof(int)))
	{
		CloseHandle((HANDLE)hFile);

		Sleep(CLOSE_TIME);
		return 0;
	}

	if (!ReadFile((HANDLE)hFile, readBuf, viSize, &bytesRead, NULL))
	{
		CloseHandle((HANDLE)hFile);

		printf("ReadFile() failed: %d. Make sure that you entered currect file path. Quiting...\n", GetLastError());

		Sleep(CLOSE_TIME);
		return 0;
	}

	if (encrypt)
	{
		EncryptCSO((int*)readBuf, viSize);
	}
	else
	{
		DecryptCSO((int*)readBuf, viSize);
	}

	// get file name from path
	char* fileName = PathFindFileName(inputFilePath);

	// remove extension
	PathRemoveExtension(fileName);

	// remove filename from filepath
	PathRemoveFileSpecA(inputFilePath);

	if (encrypt)
	{
		sprintf(outputFilePath, "%s\\%s_enc.cso", inputFilePath, fileName);
	}
	else
	{
		sprintf(outputFilePath, "%s\\%s_dec.cso", inputFilePath, fileName);
	}

	// now create decrypted file
	newFile = (HFILE)CreateFile(outputFilePath,
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (newFile == HFILE_ERROR)
	{
		printf("Could not create file: %d. Quiting...\n", GetLastError());

		Sleep(CLOSE_TIME);
		return 0;
	}

	// write decrypted data to file
	WriteFile((HANDLE)newFile, readBuf, bytesRead, &bytesWritten, NULL);

	// save decrypted file
	CloseHandle((HANDLE)newFile);
	CloseHandle((HANDLE)hFile);

	printf("Operation completed.\n");

	Sleep(CLOSE_TIME);
	return 0;
}

