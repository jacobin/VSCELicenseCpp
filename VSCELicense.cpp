// refs:
//   1. <Is Visual Studio Community a 30 day trial?> -- 
// 	     https://stackoverflow.com/questions/43390466/
// 	     is-visual-studio-community-a-30-day-trial/51570570#51570570
// 	 2. <Trial period reset of Visual Studio Community Edition> -- 
// 	     https://dimitri.janczak.net/2019/07/13/
// 	     trial-period-reset-of-visual-studio-community-edition/
#include <windows.h>
#include <ShlObj_core.h>
#include <shlobj.h>
#include <dpapi.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <time.h>

#include <memory>
#include <vector>
#include <array>
#include <string>
#include <ctime>

#pragma comment(lib,"crypt32.lib")

bool GetRegCryptedVsLicensesData(std::shared_ptr<BYTE[]>& binData,
	DWORD& dataSize, const char* regSubKey)
{
	if (ERROR_SUCCESS !=
		RegGetValueA(HKEY_CLASSES_ROOT, regSubKey, nullptr, RRF_RT_REG_BINARY,
			nullptr, nullptr, &dataSize))
	{
		return false;
	}
	binData = std::shared_ptr<BYTE[]>(new BYTE[dataSize]);
	if (ERROR_SUCCESS !=
		RegGetValueA(HKEY_CLASSES_ROOT, regSubKey, nullptr, RRF_RT_REG_BINARY,
			nullptr, binData.get(), &dataSize))
	{
		return false;
	}
	return true;
}

bool SetRegCryptedVsLicensesData(const std::shared_ptr<BYTE[]>& binData,
	DWORD dataSize, const char* regSubKey)
{
	auto resultState =
		RegSetKeyValueA(HKEY_CLASSES_ROOT, regSubKey, 0, REG_BINARY,
			(LPVOID)binData.get(), dataSize);
	return ERROR_SUCCESS == resultState;
}

// https://www.cplusplus.com/forum/beginner/3067
template<typename IntegerType>
IntegerType bitsToInt(IntegerType& result, const BYTE* bits,
	bool little_endian = true)
{
	result = 0;
	if (little_endian)
		for (int n = sizeof(result); n >= 0; n--)
			result = (result << 8) + bits[n];
	else
		for (unsigned n = 0; n < sizeof(result); n++)
			result = (result << 8) + bits[n];
	return result;
}

// https://www.cplusplus.com/forum/beginner/155821
using byte = unsigned char;
template<typename T> std::array<byte, sizeof(T)> to_bytes(const T& object)
{
	std::array<byte, sizeof(T)> bytes;
	const byte* begin = reinterpret_cast<const byte*>(std::addressof(object));
	const byte* end = begin + sizeof(T);
	std::copy(begin, end, std::begin(bytes));

	return bytes;
}

template<typename T>
T& from_bytes(const std::array<byte, sizeof(T) >& bytes, T& object)
{
	static_assert(std::is_trivially_copyable<T>::value
		, "not a TRiviallyCopyable type");
	byte* const begin_object = reinterpret_cast<byte*>(std::addressof(object));
	std::copy(std::begin(bytes), std::end(bytes), begin_object);

	return object;
}

#define ShortByte(pDat, zDat, b, e) \
	(std::array<BYTE, sizeof(short)>{{pDat[zDat-b],pDat[zDat-e]}})
bool DecodeLicensesExpirationDate(short& yyyy, short& mm, short& dd,
	std::shared_ptr<BYTE[]>& dataOut, DWORD& size,
	const std::shared_ptr<BYTE[]>& dataIn, const DWORD sizeIn)
{
	DATA_BLOB _DataOut = { 0,NULL };
	DATA_BLOB _DataIn = { 0,NULL };
	_DataIn.cbData = sizeIn;
	_DataIn.pbData = dataIn.get();
	if (!CryptUnprotectData(&_DataIn, NULL, NULL, NULL, NULL, 0, &_DataOut))
	{
		return false;
	}

	const BYTE* const pDat = _DataOut.pbData;
	const int zDat = _DataOut.cbData;
	//yyyy = bitsToInt<short>(yyyy, &pDat[zDat - 16], true);
	//mm   = bitsToInt<short>(mm,   &pDat[zDat - 14], true);
	//dd   = bitsToInt<short>(dd,   &pDat[zDat - 12], true);
	yyyy = from_bytes<short>(ShortByte(pDat, zDat, 16, 15), yyyy);
	mm = from_bytes<short>(ShortByte(pDat, zDat, 14, 13), mm);
	dd = from_bytes<short>(ShortByte(pDat, zDat, 12, 11), dd);

	BYTE* const tmp(new BYTE[_DataOut.cbData]);
	memcpy(tmp, _DataOut.pbData, _DataOut.cbData);
	dataOut = std::shared_ptr<BYTE[]>(tmp);
	size = zDat;
	LocalFree(_DataOut.pbData);

	return true;
}

bool EncodeLicensesExpirationDate(std::shared_ptr<BYTE[]>& datOut, DWORD& size,
	const std::shared_ptr<BYTE[]>& dataIn, const DWORD sizeIn,
	short yyyy, short mm, short dd)
{
	const auto byYyyy = to_bytes(yyyy);
	const auto byMm = to_bytes(mm);
	const auto byDd = to_bytes(dd);

	PBYTE p(&dataIn.get()[sizeIn - 16]);
	*p++ = byYyyy[0];
	*p++ = byYyyy[1];
	*p++ = byMm[0];
	*p++ = byMm[1];
	*p++ = byDd[0];
	*p++ = byDd[1];

	DATA_BLOB _DataOut = { 0,NULL };
	DATA_BLOB _DataIn = { 0,NULL };
	_DataIn.cbData = sizeIn;
	_DataIn.pbData = dataIn.get();
	if (!CryptProtectData(&_DataIn, NULL, NULL, NULL, NULL, 0, &_DataOut))
	{
		return false;
	}

	BYTE* const tmp(new BYTE[_DataOut.cbData]);
	memcpy(tmp, _DataOut.pbData, _DataOut.cbData);
	datOut = std::shared_ptr<BYTE[]>(tmp);
	size = _DataOut.cbData;
	LocalFree(_DataOut.pbData);

	return true;
}

#define LEAP_YEAR ((0 != year%100 && 0 == year%4) || 0 == year%400 )
#define BIG_MONTH (1 == month || 3 == month || 5 == month || 7 == month || \
                    8 == month || 10 == month || 12 == month )
#define SMALL_MONTH (4 == month || 6 == month || 9 == month || 11 == month)
#define LEAP_MONTH (2 == month)
bool isLegalDate(short year, short month, short day)
{
	if (year < 0)
	{
		return false;
	}

	if (month < 1 || 12 < month)
	{
		return false;
	}

	if (BIG_MONTH)
	{
		if (!(1 <= day && day <= 31))
		{
			return false;
		}
	}
	else if (SMALL_MONTH)
	{
		if (!(1 <= day && day <= 30))
		{
			return false;
		}
	}
	else
	{
		assert(LEAP_MONTH);
		if (LEAP_YEAR)
		{
			if (!(1 <= day && day <= 29))
			{
				return false;
			}
		}
		else
		{
			if (!(1 <= day && day <= 28))
			{
				return false;
			}
		}
	}
	return true;
}

#define VSLICENSEKEYS "Licenses\\41717607-F34E-432C-A138-A3CFD7E25CDA"

bool GetLicensesKey(std::vector<std::string>& vKeys)
{
	HKEY hKey;
	const LSTATUS lRet = RegOpenKeyExA(HKEY_CLASSES_ROOT, VSLICENSEKEYS, 0,
		KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &hKey);
	if (lRet != ERROR_SUCCESS)
	{
		return false;
	}

	for (int i(0); true; )
	{
		char thisKey[1024];
		DWORD thisKeyLen = sizeof(thisKey);
		ZeroMemory(thisKey, sizeof(thisKey));
		const LSTATUS ret = RegEnumKeyExA(hKey, i++, thisKey, &thisKeyLen,
			NULL, NULL, NULL, NULL);
		if (ERROR_SUCCESS != ret)
		{
			break;
		}
		vKeys.push_back(thisKey);
	}
	RegCloseKey(hKey);
	return true;
}

int main(int argc, char* argv[])
{
	if (!IsUserAnAdmin())
	{
		printf("Superuser privileges must be required to run this program\n");
		return -1;
	}
	std::vector<std::string> vKeys;
	vKeys.reserve(100);
	if (!GetLicensesKey(vKeys))
	{
		printf("Failed to enumerate HKEY_CLASSES_ROOT\\%s in the registry\n",
			VSLICENSEKEYS);
		return -2;
	}

	const auto keyCount = vKeys.size();
	for (std::remove_const<decltype(keyCount)>::type i = 0; i < keyCount; i++)
	{
		short yyyy(0), mm(0), dd(0);

		const std::string thisLicensesKey
		(std::string(VSLICENSEKEYS) + '\\' + vKeys[i]);
		const char* subkey(thisLicensesKey.c_str());

		// data, dataSize
		std::shared_ptr<BYTE[]> data(nullptr);
		DWORD dataSize(0);
		if (!GetRegCryptedVsLicensesData(data, dataSize, subkey))
		{
			continue;
		}

		// yyyy, mm, dd
		std::shared_ptr<BYTE[]> dataUnprotect(nullptr);
		DWORD sizeUnprotect(0);
		if (!DecodeLicensesExpirationDate(yyyy, mm, dd, dataUnprotect,
			sizeUnprotect, data, dataSize))
		{
			continue;
		}

		// check { yyyy, mm, dd }
		if (!isLegalDate(yyyy, mm, dd))
		{
			continue;
		}

		// adjust { yyyy, mm, dd }
		const time_t expirateDate(time(0) + 3600 * 24 * 30);
		struct tm locTm;
		auto err = localtime_s(&locTm, &expirateDate);
		if (0 != err)
		{
			continue;
		}
		yyyy = locTm.tm_year + 1900;
		mm = locTm.tm_mon + 1;
		dd = locTm.tm_mday;

		std::shared_ptr<BYTE[]> dataProtect(nullptr);
		DWORD sizeProtect(0);
		if (!EncodeLicensesExpirationDate(dataProtect, sizeProtect,
			dataUnprotect, sizeUnprotect, yyyy, mm, dd))
		{
			continue;
		}

		if (!SetRegCryptedVsLicensesData(dataProtect, sizeProtect, subkey))
		{
			continue;
		}

		printf("%s success\n", subkey);
	}

	return 0;
}