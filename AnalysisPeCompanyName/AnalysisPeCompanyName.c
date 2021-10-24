// 1.cpp : Defines the entry point for the console application.
//
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

//////////////////////////////////////////////////////////////////////////

//#define FILE_PATH_IN		"C:\\ipmsg.exe"


#define DWORD_ALIGN(offset, base) \
    (((offset + base + 3) & 0xfffffffcL) - (base & 0xfffffffcL))

typedef struct tag_VS_VERSIONINFO
{
	WORD             wLength;        // 00 length of entire version resource
	WORD             wValueLength;   // 02 length of fixed file info, if any
	WORD             wType;          // 04 type of resource (1 = text, 0 = binary)
	WCHAR            szKey[16];      // 06 key -- VS_VERSION_INFO
	WORD             Padding1;       // 26 padding byte 1
	VS_FIXEDFILEINFO Value;          // 28 fixed information about this file (13 dwords)
	//WORD             Padding2;
	//WORD             Children;
} VS_VERSIONINFO, *PVS_VERSIONINFO;   // 5C


typedef struct {
	WORD   wLength;
	WORD   wValueLength;
	WORD   wType;
	WCHAR  szKey[15]; // WCHAR L"VarFileInfo"
	// WORD Padding;
} FileInfo, *PFileInfo;

typedef struct {
	WORD   wLength;
	WORD   wValueLength;
	WORD   wType;
	WCHAR  szKey[12]; // WCHAR L"VarFileInfo"
	// WORD Padding;
	WORD    Children[1];
} VarFileInfo, *PVarFileInfo;


typedef struct {
	WORD   wLength;
	WORD   wValueLength;
	WORD   wType;
	WCHAR  szKey[1]; // WCHAR L"String"
	//WORD Padding;
	//WCHAR Value[1];
} String, *PString;

typedef struct {
	WORD   wLength;
	WORD   wValueLength;
	WORD   wType;
	WCHAR  szKey[9]; // WCHAR L"88888888"
	//WORD Padding;
	String Children[1];
} StringTable, *PStringTable;


typedef struct {
	WORD   wLength;
	WORD   wValueLength;
	WORD   wType;
	WCHAR  szKey[15]; // WCHAR L"StringFileInfo"
	//WORD Padding;
	StringTable Children[1];
} StringFileInfo, *PStringFileInfo;


//资源类型名称
static char* szResName[0x11] = {
	0,
	"Corsor",
	"Bitmap",
	"Icon",
	"Menu",
	"Dialog",
	"StringTable",
	"FontDir",
	"Font",
	"Accelerator",
	"RCDATA",
	"MessageTable",
	"GroupCursor",
	"zz",
	"GroupIcon",
	"xx",
	"Version"
};

//////////////////////////////////////////////////////////////////////////


size_t ReadPEFile(IN LPSTR lpszFile, OUT LPVOID* pFileBuffer)
{
	FILE *pFile = NULL;
	LPVOID pTempFileBuffer = NULL;

	DWORD fileSize = 0;
	size_t n = 0;

	//打开文件
	pFile = fopen(lpszFile, "rb");
	if (pFile == NULL)
	{
		printf("无法打开exe文件！	%d \n", GetLastError());
		return 0;
	}

	//读取文件大小
	fseek(pFile, 0L, SEEK_END);
	fileSize = (DWORD)(ftell(pFile));
	fseek(pFile, 0L, SEEK_SET);

	//分配缓冲区
	pTempFileBuffer = calloc(fileSize, sizeof(char));
	if (pTempFileBuffer == NULL)
	{
		printf("申请空间失败！\n");
		fclose(pFile);
		return 0;
	}

	//将文件数据读取到缓冲区
	n = fread(pTempFileBuffer, sizeof(char), fileSize, pFile);
	if (!n)
	{
		printf("读取数据失败！\n");
		free(pTempFileBuffer);
		pTempFileBuffer = NULL;
		fclose(pFile);
		return 0;
	}

	//关闭文件
	*pFileBuffer = pTempFileBuffer;
	pTempFileBuffer = NULL;

	fclose(pFile);
	return n;
}

DWORD RVA2FOA(IN DWORD stRVA, IN LPVOID lpFileBuffer, BOOLEAN	Is64Bit)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS64 pNTHeader = NULL;
	PIMAGE_NT_HEADERS32 pNTHeader32 = NULL;
	PIMAGE_OPTIONAL_HEADER64 pOptionHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader32 = NULL;

	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	//区段数
	DWORD dwSectionCount = 0;
	//内存对齐大小
	DWORD dwMemAlignCount = 0;
	//距离指定节的起始虚拟地址的偏移值
	DWORD dwDiffer = 0;

	if (Is64Bit)
	{

		pDosHeader = (PIMAGE_DOS_HEADER)lpFileBuffer;
		pNTHeader = (PIMAGE_NT_HEADERS64)((ULONG64)lpFileBuffer + pDosHeader->e_lfanew);
		pPEHeader = (PIMAGE_FILE_HEADER)((ULONG64)pNTHeader + sizeof(pNTHeader->Signature));
		pOptionHeader = (PIMAGE_OPTIONAL_HEADER64)((ULONG64)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);

		dwMemAlignCount = pOptionHeader->SectionAlignment;
		pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG64)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	}
	else
	{
		pDosHeader = (PIMAGE_DOS_HEADER)lpFileBuffer;
		pNTHeader32 = (PIMAGE_NT_HEADERS32)((ULONG64)lpFileBuffer + pDosHeader->e_lfanew);
		pPEHeader = (PIMAGE_FILE_HEADER)((ULONG64)pNTHeader32 + sizeof(pNTHeader32->Signature));
		pOptionHeader32 = (PIMAGE_OPTIONAL_HEADER32)((ULONG64)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);

		dwMemAlignCount = pOptionHeader32->SectionAlignment;
		pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG64)pOptionHeader32 + pPEHeader->SizeOfOptionalHeader);
	}

	dwSectionCount = pPEHeader->NumberOfSections;

	for (DWORD i = 0; i < dwSectionCount; i++, pSectionHeader++)
	{
		//模拟内存对齐机制
		DWORD dwBlockCount = pSectionHeader->SizeOfRawData / dwMemAlignCount;
		dwBlockCount += (pSectionHeader->SizeOfRawData % dwMemAlignCount ? 1 : 0);

		DWORD dwBeginVA = pSectionHeader->VirtualAddress;
		DWORD dwEndVA = pSectionHeader->VirtualAddress + dwBlockCount * dwMemAlignCount;

		//如果 stRVA 在某个区段中
		if (stRVA >= dwBeginVA && stRVA < dwEndVA)
		{
			dwDiffer = stRVA - dwBeginVA;
			return (pSectionHeader->PointerToRawData + dwDiffer);
		}
		else if (stRVA < dwBeginVA) //在文件头中直接返回
		{
			return stRVA;
		}
	}



	return 0;
}

BOOLEAN		AnalysisFileVersion(DWORD OffsetToData, PVOID	Buffer, PWCHAR		szKey, PWCHAR	OutValue, BOOLEAN	Is64Bit)
{
	int Fva = RVA2FOA(OffsetToData, Buffer, Is64Bit);
	PVS_VERSIONINFO	pVersionInfo = (PVS_VERSIONINFO)(Fva + (PUCHAR)Buffer);
	PFileInfo		pfInfo = NULL;
	int				VersionInfoLength = pVersionInfo->wLength;

	pfInfo = (PFileInfo)pVersionInfo;
	do
	{
		pfInfo = (PFileInfo)((PUCHAR)pfInfo + sizeof(VS_VERSIONINFO));
		VersionInfoLength -= sizeof(VS_VERSIONINFO);

		if (wcscmp(pfInfo->szKey, L"StringFileInfo") == 0)
		{
			//	毫无规律，szKey 与 Value 是为0结尾的字符串
			PStringFileInfo		pStringFileInfo = (PStringFileInfo)pfInfo;
			int	StringFileInfoLength = (int)pStringFileInfo->wLength;
			PString	StringArray = &pStringFileInfo->Children[0].Children[0];
			DWORD		ValueLength = 0;


			PString i = &pStringFileInfo->Children[0].Children[0];
			ULONG64	StringTablelimit = (ULONG64)&pStringFileInfo->Children[0] + pStringFileInfo->Children[0].wLength;
			PWCHAR	FindValuie = NULL;


			do
			{
				if (i->wLength == 0)
				{
					i = (PString)((PUCHAR)i + 2);
				}

				if (wcscmp(i->szKey, szKey) == 0)
				{
					int	Number = 0;
					FindValuie = wcschr((i->szKey + sizeof(WCHAR)), '\0');

					while ((i->wValueLength) && ((wcslen(FindValuie) + 1) != i->wValueLength))
					{
						++FindValuie;
						++Number;
						if (Number == 10)
							break;

					}
					wcscpy_s(OutValue, i->wValueLength, FindValuie);
					return	TRUE;
				}

				i = (PString)((ULONG64)i + i->wLength);

			} while ((ULONG64)i < StringTablelimit);

			if (wcscmp(i->szKey, szKey) == 0)
			{
				FindValuie = wcschr((i->szKey + sizeof(WCHAR)), '\0');
				wcscpy_s(OutValue, i->wValueLength, ++FindValuie);
				return	TRUE;
			}

		}
	} while (VersionInfoLength >= 0);

	return FALSE;
}

// L"Comments"          // 为诊断信息展示的附加信息
// L"CompanyName"       // 公司名称
// L"FileDescription"   // 文件描述
// L"FileVersion"       // 文件版本
// L"InternalName"      // 内部名称
// L"LegalCopyright"    // 版权信息
// L"LegalTrademarks"   // 应用于该文件的商标或注册商标
// L"OriginalFilename"  // 原始文件名
// L"PrivateBuild"      // PrivateBuild *
// L"ProductName"       // 产品名称
// L"ProductVersion"    // 产品版本
// L"SpecialBuild"      // SpecialBuild *

BOOLEAN		Help_GetFileVersionInfo(PVOID	pFileBuffer, PWCHAR		szKey, PWCHAR	OutValue)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;

	PIMAGE_NT_HEADERS64 pNtHeader = NULL;
	PIMAGE_NT_HEADERS32 pNtHeader32 = NULL;

	PIMAGE_OPTIONAL_HEADER64 pOptionHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader32 = NULL;

	PIMAGE_FILE_HEADER pPEHeader = NULL;

	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_RESOURCE_DIRECTORY pResourceTable = NULL;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pResourceEntry = NULL;

	BOOLEAN		Flags = FALSE;
	BOOLEAN		Res = TRUE;
	BOOLEAN		Is64Bit = FALSE;

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNtHeader = (PIMAGE_NT_HEADERS64)((ULONG64)pDosHeader + pDosHeader->e_lfanew);


	pPEHeader = (PIMAGE_FILE_HEADER)((ULONG64)pNtHeader + sizeof(pNtHeader->Signature));

	if (pNtHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
	{
		pOptionHeader32 = (PIMAGE_OPTIONAL_HEADER32)((ULONG64)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
		pDataDirectory = (PIMAGE_DATA_DIRECTORY)(&pOptionHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE]);
		Is64Bit = FALSE;
	}
	else if (pNtHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		pOptionHeader = (PIMAGE_OPTIONAL_HEADER64)((ULONG64)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
		pDataDirectory = (PIMAGE_DATA_DIRECTORY)(&pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE]);
		Is64Bit = TRUE;
	}
	else
		return FALSE;


	//定义资源表

	DWORD dwResourceRVA = RVA2FOA(pDataDirectory->VirtualAddress, pDosHeader, Is64Bit);
	pResourceTable = (PIMAGE_RESOURCE_DIRECTORY)((ULONG64)pDosHeader + dwResourceRVA);

	//资源表内第一层：类型
	DWORD dwTypeSize = pResourceTable->NumberOfIdEntries + pResourceTable->NumberOfNamedEntries;
	pResourceEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceTable + 1);

	//遍历第一层：资源类型
	for (DWORD i = 0; i < dwTypeSize; i++)
	{
		//最高位为0
		if (!pResourceEntry[i].NameIsString)
		{
			if (pResourceEntry[i].Id < 0x11)
			{
				if (pResourceEntry[i].Name == RT_VERSION)
				{
					Flags = TRUE;
				}
			}
		}

		//解析第二层目录
		if (pResourceEntry[i].DataIsDirectory) //1
		{
			PIMAGE_RESOURCE_DIRECTORY pRes2 = (PIMAGE_RESOURCE_DIRECTORY)((ULONG64)pResourceTable + pResourceEntry[i].OffsetToDirectory);
			DWORD dwCount = pRes2->NumberOfIdEntries + pRes2->NumberOfNamedEntries;
			PIMAGE_RESOURCE_DIRECTORY_ENTRY pResEntry2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pRes2 + 1);

			for (DWORD i = 0; i < dwCount; i++)
			{
				//解析第三层目录
				PIMAGE_RESOURCE_DIRECTORY pRes3 = (PIMAGE_RESOURCE_DIRECTORY)((ULONG64)pResourceTable + pResEntry2[i].OffsetToDirectory);
				PIMAGE_RESOURCE_DIRECTORY_ENTRY pResEntry3 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pRes3 + 1);
				if (!pResEntry3[i].DataIsDirectory)
				{
					//取数据偏移，显示数据
					PIMAGE_RESOURCE_DATA_ENTRY pResData = (PIMAGE_RESOURCE_DATA_ENTRY)((ULONG64)pResourceTable + pResEntry3->OffsetToData);

					if (Flags == TRUE)
					{
						return	AnalysisFileVersion(pResData->OffsetToData, pDosHeader, szKey, OutValue, Is64Bit);
					}

				}
			}
		}
		else
		{
			//取数据偏移，显示数据
			PIMAGE_RESOURCE_DATA_ENTRY pResData = (PIMAGE_RESOURCE_DATA_ENTRY)((ULONG64)pResourceTable + pResourceEntry[i].OffsetToData);
			if (Flags == TRUE)
			{
				return	AnalysisFileVersion(pResData->OffsetToData, pDosHeader, szKey, OutValue, Is64Bit);
			}
		}
	}

	return FALSE;

}

#define FILE_PATH_IN		"E:\\cloudmusic.exe"
VOID TestPrintResourceTable()
{


	LPVOID	pFileBuffer = NULL;
	size_t	dwSize = 0;
	WCHAR	OutValue[MAX_PATH] = { 0 };

	dwSize = ReadPEFile(FILE_PATH_IN, &pFileBuffer);
	if (dwSize == 0 || pFileBuffer == NULL)
	{
		printf("读取文件失败！\n");
	}

	Help_GetFileVersionInfo(pFileBuffer, L"CompanyName", OutValue);


	system("pause");
}



int main()
{
	TestPrintResourceTable();


	system("pause");
	return 0;
}