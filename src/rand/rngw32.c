/**
 * Copyright (C) 2024-25  Xrand
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "rngw32.h"
#include "crypto/crc.h"
#include "jitterentropy/jitterentropy.h"
#include "rdrand.h"

#include <bcrypt.h>
#include <iphlpapi.h>
#include <process.h>
#include <stdlib.h>
#include <tchar.h>
#include <strsafe.h>
#include <wchar.h>

#pragma intrinsic(__rdtsc)

/* The randomness pool */
static uint8_t *pRandPool = NULL;
static UINT nCurrentPoolWritePos = 0;
static UINT nCurrentPoolReadPos = 0;

/* The fast poll thread handle */
static HANDLE hPeriodicFastPollThreadHandle = NULL;

BOOL bStrictChecksEnabled = FALSE;
BOOL bUserEventsEnabled = FALSE;

/* Internal control and status variables */
static BOOL bDidRandPoolInit = FALSE;
static BOOL bDidSlowPoll = FALSE;
static BOOL bIsWin32CngAvailable = FALSE;

/* Global status variables for RDRAND and RDSEED */
BOOL bHasRdrand = FALSE;
BOOL bHasRdseed = FALSE;

/* Global BCrypt API handles */
static HMODULE hBCrypt = NULL;
static BCRYPT_ALG_HANDLE hBCryptProv = NULL;
DWORD dwWin32CngLastErr = -1;

/* Global Win32 API handles */
static HMODULE hWinNativeApi = NULL;
static HMODULE hIpHlpApi = NULL;
static HANDLE hNetApi32 = NULL;

DWORD dwErrCode = -1;

volatile int nUserEventsAdded = 0;

/* The mouse and keyboard hook handles */
static HHOOK hMouseHook = NULL;
static HHOOK hKbdHook = NULL;

/* The critical section */
CRITICAL_SECTION randCritSec;
/* Thread control variable for the fast poll thread */
BOOL volatile bTerminateFastPollThread = FALSE;

/* 64 byte buffer */
typedef struct _BUF_ST {
  size_t size;
  union {
    uint8_t bytes[64];
    uint32_t words[64 / 4];
  };
} BUF, *PBUF;

/* Add a single byte to the pool */
#define AddByte(x)                                                             \
  do {                                                                         \
    if (nCurrentPoolWritePos % RNG_POOL_MIX_INTERVAL == 0)                     \
      RandPoolMix();                                                           \
    if (nCurrentPoolWritePos == RNG_POOL_SIZE)                                 \
      nCurrentPoolWritePos = 0;                                                \
    pRandPool[nCurrentPoolWritePos++] ^= (uint8_t)x;                           \
  } while (0)

/* Add a pointer to the pool */
#ifdef _WIN64
#define AddPtr(x) Add64((uint64_t)x);
#else
#define AddPtr(x) Add32((uint32_t)x);
#endif

/* Adding multiple bytes to the pool */

void Add8(uint8_t x) { AddByte(x); }

void Add16(uint16_t x) {
  AddByte(x);
  AddByte((x >> 8));
}

void Add32(uint32_t x) {
  AddByte(x);
  AddByte((x >> 8));
  AddByte((x >> 16));
  AddByte((x >> 24));
}

void Add64(uint64_t x) {
  AddByte(x);
  AddByte((x >> 8));
  AddByte((x >> 16));
  AddByte((x >> 24));
  AddByte((x >> 32));
  AddByte((x >> 40));
  AddByte((x >> 48));
  AddByte((x >> 56));
}

/* Add a buffer to the pool */
static void AddBuf(uint8_t *buf, size_t size) {
  for (size_t i = 0; i < size; ++i) {
    AddByte(buf[i]);
  }
}

/* Type definitions and function pointers to call the CNG API functions */
typedef NTSTATUS(WINAPI *BCRYPTOPENALGORITHMPROVIDER)(
    BCRYPT_ALG_HANDLE *phAlgorithm, LPCWSTR pszAlgId, LPCWSTR pszImplementation,
    ULONG dwFlags);

typedef NTSTATUS(WINAPI *BCRYPTGENRANDOM)(BCRYPT_ALG_HANDLE hAlgorithm,
                                          PUCHAR pbBuffer, ULONG cbBuffer,
                                          ULONG dwFlags);

typedef NTSTATUS(WINAPI *BCRYPTCLOSEALGORITHMPROVIDER)(
    BCRYPT_ALG_HANDLE hAlgorithm, ULONG dwFlags);

static BCRYPTOPENALGORITHMPROVIDER pBCryptOpenAlgorithmProvider = NULL;
static BCRYPTGENRANDOM pBCryptGenRandom = NULL;
static BCRYPTCLOSEALGORITHMPROVIDER pBCryptCloseAlgorithmProvider = NULL;

/**
 * Initialize the  Random Number Generator.   Mount the pool  onto
 * memory, start the fast  poll thread, load and init the  Windows
 * CNG randomness provider.
 *
 * Allocate RNG_POOL_SIZE  bytes of memory for the randomness pool
 * and Lock the region to physical memory to prevent the pool from
 * being paged to the disk.
 */
BOOL RandPoolInit(void) {
  if (bDidRandPoolInit)
    return TRUE;

  nCurrentPoolWritePos = 0;
  nCurrentPoolReadPos = 0;

  InitializeCriticalSection(&randCritSec);

  pRandPool = _aligned_malloc(RNG_POOL_SIZE, 8);

  if (pRandPool == NULL) {
    Log(ERR_NO_MEMORY, FALSE, errno, __LINE__);
    return FALSE;
  }

  if (VirtualLock(pRandPool, RNG_POOL_SIZE) == 0) {
    _aligned_free(pRandPool);
    Log(ERR_RAND_INIT, FALSE, GetLastError(), __LINE__);
    return FALSE;
  }

  bDidRandPoolInit = TRUE;

  dwWin32CngLastErr = ERROR_SUCCESS;

  /* Load the BCrypt library and initialize the CNG API function pointers */
  if ((hBCrypt = LoadLibrary("bcrypt.dll")) == NULL) {
    dwWin32CngLastErr = GetLastError();
    Log(ERR_WIN32_CNG, FALSE, dwWin32CngLastErr, __LINE__);
    goto err;
  } else {
    pBCryptOpenAlgorithmProvider = (BCRYPTOPENALGORITHMPROVIDER)GetProcAddress(
        hBCrypt, "BCryptOpenAlgorithmProvider");
    pBCryptGenRandom =
        (BCRYPTGENRANDOM)GetProcAddress(hBCrypt, "BCryptGenRandom");
    pBCryptCloseAlgorithmProvider =
        (BCRYPTCLOSEALGORITHMPROVIDER)GetProcAddress(
            hBCrypt, "BCryptCloseAlgorithmProvider");

    if (!pBCryptOpenAlgorithmProvider || !pBCryptGenRandom ||
        !pBCryptCloseAlgorithmProvider) {
      dwWin32CngLastErr = GetLastError();
      Log(ERR_WIN32_CNG, FALSE, dwWin32CngLastErr, __LINE__);
      goto err;
    }

    /* Use BCRYPT_RNG_ALGORITHM as the underlying random number
       generation algorithm  for BCryptGenRandom() which is the
       AES-256 counter mode based random  generator  as defined
       in SP800-90. */
    if (BCryptOpenAlgorithmProvider(&hBCryptProv, BCRYPT_RNG_ALGORITHM, NULL,
                                    0) != ERROR_SUCCESS) {
      dwWin32CngLastErr = GetLastError();
      Log(ERR_WIN32_CNG, FALSE, dwWin32CngLastErr, __LINE__);
      goto err;
    } else {
      bIsWin32CngAvailable = TRUE;
    }
  }

  if (rdrand_check_support())
    bHasRdrand = TRUE;
  if (rdseed_check_support())
    bHasRdseed = TRUE;

  if (!(hPeriodicFastPollThreadHandle =
            (HANDLE)_beginthreadex(NULL, 0, FastPollThreadProc, NULL, 0, NULL)))
    goto err;

  return TRUE;

err:
  dwErrCode = GetLastError();
  SetLastError(dwErrCode);
  RandCleanStop();
  return FALSE;
}

/**
 * Safely stop RNG, release all hooks,  terminate the thread, reset
 * all  global  status and  control flags  and free any dynamically
 * loaded modules, if necessary.
 *
 * Stops the thread by setting a control flag which will eventually
 * cause the thread proc to exit.
 *
 * Unlock the  pool and clear it to zero before freeing the memory.
 */
void RandCleanStop(void) {
  if (!bDidRandPoolInit)
    return;

  EnterCriticalSection(&randCritSec);

  if (hMouseHook != NULL) {
    UnhookWindowsHookEx(hMouseHook);
    hMouseHook = NULL;
  }
  if (hKbdHook != NULL) {
    UnhookWindowsHookEx(hKbdHook);
    hKbdHook = NULL;
  }

  bTerminateFastPollThread = TRUE;

  LeaveCriticalSection(&randCritSec);

  if (hPeriodicFastPollThreadHandle != NULL)
    WaitForSingleObject(hPeriodicFastPollThreadHandle, INFINITE);

  if (bIsWin32CngAvailable) {
    pBCryptCloseAlgorithmProvider(hBCryptProv, 0);
    bIsWin32CngAvailable = FALSE;
    hBCryptProv = NULL;
    dwWin32CngLastErr = -1;
  }

  if (hBCrypt != NULL) {
    FreeLibrary(hBCrypt);
    hBCrypt = NULL;
  }

  if (hWinNativeApi != NULL) {
    FreeLibrary(hWinNativeApi);
    hWinNativeApi = NULL;
  }

  if (hIpHlpApi != NULL) {
    FreeLibrary(hIpHlpApi);
    hIpHlpApi = NULL;
  }

  if (hNetApi32 != NULL) {
    FreeLibrary(hNetApi32);
    hNetApi32 = NULL;
  }

  hPeriodicFastPollThreadHandle = NULL;

  DeleteCriticalSection(&randCritSec);

  /* Unlock, clear and free the randomness pool */
  VirtualUnlock(pRandPool, RNG_POOL_SIZE);
  zeroize(pRandPool, RNG_POOL_SIZE);
  _aligned_free(pRandPool);

  pRandPool = NULL;
  bStrictChecksEnabled = FALSE;
  bDidRandPoolInit = FALSE;
  bDidSlowPoll = FALSE;
  nCurrentPoolWritePos = 0;
  nCurrentPoolReadPos = 0;
}

/* The thread procedure called periodically to poll for system entropy. */
static unsigned __stdcall FastPollThreadProc(void *_dummy) {
  UNREFERENCED_PARAMETER(_dummy);

  for (;;) {
    EnterCriticalSection(&randCritSec);

    if (bTerminateFastPollThread) {
      bTerminateFastPollThread = FALSE;
      LeaveCriticalSection(&randCritSec);
      _endthreadex(0);
    } else {
      RandFastPoll();
    }

    LeaveCriticalSection(&randCritSec);

    Sleep(RNG_FAST_POLL_INTERVAL);
  }
}

/**
 * Enumerate all top-level windows on the screen using
 * EnumWindows() and add the window information to the
 * randomness pool.
 */
BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {
  if (!hWnd)
    return FALSE;

  DWORD dwThreadId;
  DWORD dwProcessId;
  GUITHREADINFO gui;
  WINDOWINFO wi;

  AddPtr(hWnd); /* The window handle */
  dwThreadId = GetWindowThreadProcessId(hWnd, (LPDWORD)&dwProcessId);
  Add32(dwThreadId);  /* The window thread process ID */
  Add32(dwProcessId); /* The window thread ID */

  GetGUIThreadInfo(dwThreadId, (PGUITHREADINFO)&gui);
  AddBuf(Ptr8(&gui), sizeof(GUITHREADINFO)); /* GUI info of the thread */

  /* Get all sorts of  window information,  including the window
     client area coordinates, bounding rectangle dimensions, and
     the extended window style. */
  GetWindowInfo(hWnd, (PWINDOWINFO)&wi);
  AddBuf(Ptr8(&wi), sizeof(WINDOWINFO));

  return TRUE;
}

/**
 * Capture the mouse event, and if the mouse has moved, add its
 * CRC +  the CRC of the time delta between the current and the
 * previous event to the pool.
 */
LRESULT CALLBACK MouseProc(int nCode, WPARAM wParam, LPARAM lParam) {
  static POINT prevPt;
  static DWORD dwPrevTime;

  /* Send a WM_QUIT to the messsage queue once the sufficient
     number of events have been added */
  if (nUserEventsAdded > 256)
    PostQuitMessage(0);

  if (nCode < 0)
    return CallNextHookEx(hMouseHook, nCode, wParam, lParam);

  MSLLHOOKSTRUCT *lpMouse = (MSLLHOOKSTRUCT *)lParam;

  if ((nCode == HC_ACTION) && (wParam == WM_MOUSEMOVE) &&
      ((prevPt.x != lpMouse->pt.x) || (prevPt.y != lpMouse->pt.y))) {
    nUserEventsAdded++;

    DWORD dwTime = GetTickCount64();
    DWORD dwTimeDelta = dwTime - dwPrevTime;
    dwPrevTime = dwTime;

    uint32_t crc = 0u;
    uint32_t timeCrc = 0u;

    /* CRC of the mouse event */
    for (int i = 0; i < sizeof(MSLLHOOKSTRUCT); ++i)
      crc = UPDC32((Ptr8(&lpMouse))[i], crc);

    /* CRC of the time delta */
    for (int i = 0; i < 4; ++i)
      timeCrc = UPDC32((Ptr8(&dwTimeDelta))[i], timeCrc);

    EnterCriticalSection(&randCritSec);
    Add32((uint32_t)(crc + timeCrc));
    LeaveCriticalSection(&randCritSec);

    prevPt = lpMouse->pt;
  }

  return CallNextHookEx(hMouseHook, nCode, wParam, lParam);
}

/**
 * Capture the keyboard event, and if the key is different from
 * either of the previous two events,  add its CRC + the CRC of
 * the time delta to the pool.
 */
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
  static int prevKey, prevPrevKey;
  static DWORD dwPrevTime;

  /* Send a WM_QUIT to the messsage queue once the sufficient
     number of events have been added */
  if (nUserEventsAdded > 256)
    PostQuitMessage(0);

  if (nCode < 0)
    return CallNextHookEx(hKbdHook, nCode, wParam, lParam);

  KBDLLHOOKSTRUCT *lpKbd = (KBDLLHOOKSTRUCT *)lParam;
  DWORD flags = lpKbd->flags;
  DWORD key = lpKbd->vkCode;

  if (!(flags & 0x1) && !(flags & 0x20) && !(flags & 0x80) &&
      (key != prevKey || key != prevPrevKey)) {
    nUserEventsAdded++;

    DWORD dwTime = GetTickCount64();
    DWORD dwTimeDelta = dwTime - dwPrevTime;
    dwPrevTime = dwTime;

    uint32_t crc = 0u;
    uint32_t timeCrc = 0u;

    /* CRC of the keyboard event */
    for (int i = 0; i < sizeof(KBDLLHOOKSTRUCT); ++i)
      crc = UPDC32((Ptr8(&lpKbd))[i], crc);

    /* CRC of the time delta */
    for (int i = 0; i < 4; ++i)
      timeCrc = UPDC32((Ptr8(&dwTimeDelta))[i], timeCrc);

    EnterCriticalSection(&randCritSec);
    Add32((uint32_t)(crc + timeCrc));
    LeaveCriticalSection(&randCritSec);

    prevPrevKey = prevKey;
    prevKey = key;
  }

  return CallNextHookEx(hKbdHook, nCode, wParam, lParam);
}

/**
 * Capture the mouse and keyboard using low level hooks.
 *
 * Install the  hooks and keep the  message pump alive till
 * either of the callback procedures sends a WM_QUIT to the
 * thread's message queue.
 *
 * Note: Since low  level hooks  require a  message loop and
 * tend to  slow down  the  application,  I find it  best to
 * add user-supplied entropy only when necessary,  for e.g.,
 * when the user has requested for bytes. The number of user
 * events required  before  the message loop  can  exit  has
 * been chosen to ensure that the random  data added  covers
 * the entire  length of the  pool at  least once.  The pool
 * mixing  function is  called  before  AddUserEvents()  can
 * successfully  return to diffuse the  added data  over the
 * entire pool.
 */
BOOL AddUserEvents(void) {
  BOOL ret = TRUE;

  /* Setup the hooks */
  hMouseHook = SetWindowsHookEx(WH_MOUSE_LL, (HOOKPROC)&MouseProc, NULL, 0);
  hKbdHook = SetWindowsHookEx(WH_KEYBOARD_LL, (HOOKPROC)&KeyboardProc, NULL, 0);

  if (!hMouseHook || !hKbdHook) {
    Log(ERR_WIN32_WINAPI, FALSE, GetLastError(), __LINE__);
    ret = FALSE;
    goto exit;
  }

  /* The message loop */
  MSG msg;
  while (GetMessage(&msg, NULL, 0, 0) > 0) {
    TranslateMessage(&msg);
    DispatchMessage(&msg);
  }

  /* Mix the pool */
  RandPoolMix();

exit:
  nUserEventsAdded = 0;
  if (hMouseHook) {
    UnhookWindowsHookEx(hMouseHook);
    hMouseHook = NULL;
  }
  if (hKbdHook) {
    UnhookWindowsHookEx(hKbdHook);
    hKbdHook = NULL;
  }

  return ret;
}

/**
 * The fast poll function which gathers entropy from various basic
 * pieces of system information by calling  Windows API functions.
 */
BOOL RandFastPoll(void) {
  BUF buf;
  PBUF bufPtr = &buf;
  HANDLE handle;
  MEMORYSTATUS memoryStatus;
  SIZE_T minimumWorkingSetSize, maximumWorkingSetSize;
  FILETIME creationTime, exitTime, kernelTime, userTime;
  FILETIME systemTimeAsFileTime;
  POINT point;
  LARGE_INTEGER ticks;

  /* Request random bytes from the Windows CNG random provider */
  if (bIsWin32CngAvailable) {
    bufPtr->size = 16;
    if (pBCryptGenRandom(hBCryptProv, bufPtr->bytes, bufPtr->size, 0) ==
        ERROR_SUCCESS) {
      AddBuf(bufPtr->bytes, bufPtr->size);
    } else {
      dwWin32CngLastErr = GetLastError();
      Log(ERR_WIN32_CNG, FALSE, dwWin32CngLastErr, __LINE__);
      return FALSE;
    }
  } else {
    return FALSE;
  }

  /* Use RDSEED and RDRAND, if available, as a source of random bytes */
  {
    uint64_t rand;

    /* Request 16 bytes from RDRAND */
    if (bHasRdrand) {
      if (rdrand64_step(&rand))
        Add64(rand);

      if (rdrand64_step(&rand))
        Add64(rand);
    }

    /* Request 16 bytes from RDSEED */
    if (bHasRdseed) {
      if (rdseed64_step(&rand))
        Add64(rand);

      if (rdseed64_step(&rand))
        Add64(rand);
    }
  }

  Add32(GetCurrentProcessId()); /* Process ID for the current process */
  AddPtr(GetCurrentProcess());  /* Pseudo handle for the current processs */

  Add32(GetCurrentThreadId()); /* Thread ID for the current thread */
  AddPtr(GetCurrentThread());  /* Pseudo handle for the current thread */

  AddPtr(GetActiveWindow());     /* Active window handle */
  AddPtr(GetForegroundWindow()); /* Foreground window handle */
  AddPtr(GetShellWindow());      /* Handle to shell desktop window */
  AddPtr(GetCapture());          /* Handle to window with mouse capture */
  AddPtr(GetDesktopWindow());    /* Desktop window handle */
  AddPtr(GetFocus());            /* Handle to window with keyboard focus */

  EnumWindows(EnumWindowsProc, 0); /* Enumerate all top-level windows */

  AddPtr(GetClipboardOwner());  /* Clipboard owner handle */
  AddPtr(GetClipboardViewer()); /* Handle to the starting window in
                                   the clipboard viewer chain */
  if (OpenWindowStationW(L"WinSta0", FALSE, WINSTA_ACCESSCLIPBOARD))
    Add32(GetClipboardSequenceNumber()); /* Clipboard sequence number for
                                            the current window station */
  AddPtr(GetOpenClipboardWindow()); /* Handle to the window with the clipboard
                                       open */
  AddPtr(GetLastActivePopup(GetClipboardOwner())); /* Clipboard owner's last
                                                      active pop-up */

  Add8(GetKBCodePage()); /* Current code page */
  Add8(GetOEMCP());      /* Current OEM code page ID */

  Add32(GetCurrentTime()); /* Milliseconds since windows started */

  /* Message time and cursor position of the last message
     retrieved from the message queue of the current thread */
  Add8(GetMessageTime());
  Add32(GetMessagePos());

  AddPtr(GetProcessHeap());          /* Handle to the default process heap */
  AddPtr(GetProcessWindowStation()); /* Handle to current window station */
  Add32(GetQueueStatus(
      QS_ALLEVENTS)); /* Message types in thread's message queue */

  /* Multiword sytem information */
  GetCaretPos(&point); /* Current caret position */
  AddBuf(Ptr8(&point), sizeof(POINT));
  GetCursorPos(&point); /* Current mouse cursor position */
  AddBuf(Ptr8(&point), sizeof(POINT));

  /* Get percent of memory in use, bytes of physical memory, bytes of
     free physical memory, bytes in paging file, free bytes in paging
     file, user bytes of address space, and free user bytes. */
  memoryStatus.dwLength = sizeof(MEMORYSTATUS);
  GlobalMemoryStatus(&memoryStatus);
  AddBuf(Ptr8(&memoryStatus), sizeof(MEMORYSTATUS));

  /* Get thread and process creation time, exit time, time in kernel
     mode, and time in user mode in 100ns intervals. */
  handle = GetCurrentThread();
  GetThreadTimes(handle, &creationTime, &exitTime, &kernelTime, &userTime);
  AddBuf(Ptr8(&creationTime), sizeof(FILETIME));
  AddBuf(Ptr8(&exitTime), sizeof(FILETIME));
  AddBuf(Ptr8(&kernelTime), sizeof(FILETIME));
  AddBuf(Ptr8(&userTime), sizeof(FILETIME));

  handle = GetCurrentProcess();
  GetProcessTimes(handle, &creationTime, &exitTime, &kernelTime, &userTime);
  AddBuf(Ptr8(&creationTime), sizeof(FILETIME));
  AddBuf(Ptr8(&exitTime), sizeof(FILETIME));
  AddBuf(Ptr8(&kernelTime), sizeof(FILETIME));
  AddBuf(Ptr8(&userTime), sizeof(FILETIME));

  /* Get the minimum and maximum working set size for the
     current process. */
  GetProcessWorkingSetSize(handle, &minimumWorkingSetSize,
                           &maximumWorkingSetSize);
  AddPtr(minimumWorkingSetSize);
  AddPtr(maximumWorkingSetSize);

  /* Get the current system date and time with the
     highest possible level of precision (<1us) in
     the Coordinated Universal Time  (UTC) format. */
  GetSystemTimePreciseAsFileTime((LPFILETIME)&systemTimeAsFileTime);
  AddBuf(Ptr8(&systemTimeAsFileTime), sizeof(LPFILETIME));

  /* According  to  MS docs,  the  majority   of  Windows   systems
     (Windows 7,  Windows Server 2008 R2,  Windows 8,  Windows 8.1,
     Windows  Server  2012,  and  Windows  Server  2012  R2)   have
     processors  with  constant-rate  TSCs and  use these  counters
     as the basis for QPC.  TSCs are high-resolution  per-processor
     hardware counters  that can be accessed  with very low latency
     and overhead  (in the order of 10s or 100s of machine cycles),
     however the performance  varies  depending on  the  underlying
     architecture and the OS version.

     On Windows RT,  Windows 11,  and Windows 10  devices using Arm
     processors,  the  performance counter is  based  on  either  a
     proprietary platform counter or the system counter provided by
     the Arm Generic Timer if the platform is so equipped.

     Although QPC can fail on systems lacking the required hardware,
     on systems that  run  Windows XP or later,  the  function  will
     always return with success. */
  if (QueryPerformanceCounter(&ticks)) {
    AddBuf(Ptr8(&ticks), sizeof(LARGE_INTEGER));
  }

#if defined(__x86_64__)
  {
    /* x86-64 always has a TSC that can be read as an intrinsic. */
    Add64((uint64_t)__rdtsc());
  }
#endif

  /* Mix the pool */
  RandPoolMix();

  /* Prevent leaks */
  zeroize(bufPtr, sizeof(buf));

  return TRUE;
}

/* Type definitions and function pointers to call the native NT functions */
typedef NTSTATUS(NTAPI *NTQUERYSYSTEMINFORMATION)(ULONG SystemInformationClass,
                                                  PVOID SystemInformation,
                                                  ULONG SystemInformationLength,
                                                  PULONG ReturnLength);
static NTQUERYSYSTEMINFORMATION pNtQuerySystemInformation = NULL;

/* Type definitions and function pointers to call IP Helper API functions */
typedef DWORD(WINAPI *GETIPSTATISTICSEX)(PMIB_IPSTATS, ULONG);
typedef DWORD(WINAPI *GETTCPSTATISTICSEX)(PMIB_TCPSTATS, ULONG);

GETIPSTATISTICSEX pGetIpStatisticsEx = NULL;
GETTCPSTATISTICSEX pGetTcpStatisticsEx = NULL;

/* Type definitions and function pointers to call NETAPI32 functions */
typedef DWORD(WINAPI *NETSTATISTICSGET)(LPWSTR szServer, LPWSTR szService,
                                        DWORD dwLevel, DWORD dwOptions,
                                        LPBYTE *lpBuffer);
typedef DWORD(WINAPI *NETAPIBUFFERSIZE)(LPVOID lpBuffer, LPDWORD cbBuffer);
typedef DWORD(WINAPI *NETAPIBUFFERFREE)(LPVOID lpBuffer);

static NETSTATISTICSGET pNetStatisticsGet = NULL;
static NETAPIBUFFERSIZE pNetApiBufferSize = NULL;
static NETAPIBUFFERFREE pNetApiBufferFree = NULL;

/**
 * CoreTemp data structures to read processor temps and other
 * vital information via the shared-memory interface, defined
 * in https://www.alcpu.com/CoreTemp/developers.html.
 */

typedef struct {
  unsigned int uiLoad[256];
  unsigned int uiTjMax[128];
  unsigned int uiCoreCnt;
  unsigned int uiCPUCnt;
  /* The float values are overlayed with 32-bit
     DWORDs since the values are not important.*/
  DWORD /* float */ fTemp[256];
  DWORD /* float */ fVID;
  DWORD /* float */ fCPUSpeed;
  DWORD /* float */ fFSBSpeed;
  DWORD /* float */ fMultipier;
  DWORD /* float */ sCPUName[100];
  unsigned char ucFahrenheit;
  unsigned char ucDeltaToTjMax;
} CORE_TEMP_SHARED_DATA;

/**
 * Data structures and pre-processors to read data via the
 * GPU-Z shared memory interface (see
 * https://www.techpowerup.com/forums/threads/gpu-z-shared-memory-layout.65258).
 *
 * The memory layout is incredibly wasteful since not all
 * of this data is useful entropy. It is therefore a good
 * option to provide a way to entirely  disable access to
 * the GPU-Z shared memory.
 */

#define GPUZ_MAX_RECORDS 10

#pragma pack(push, 1)

typedef struct {
  WCHAR key[256];
  WCHAR value[256];
} GPUZ_RECORD;

typedef struct {
  WCHAR name[256];
  WCHAR unit[8];
  UINT32 digits;
  UINT64 /* double */ value;
} GPUZ_SENSOR_RECORD;

typedef struct {
  UINT32 version;     /* Version number, should be 1 */
  volatile LONG busy; /* Data-update flag */
  UINT32 lastUpdate;  /* GetTickCount() of last update */
  GPUZ_RECORD data[GPUZ_MAX_RECORDS];
  GPUZ_SENSOR_RECORD sensors[GPUZ_MAX_RECORDS];
} GPUZ_SH_MEM;

#pragma pack(pop)

/**
 * The slow poll performs a more in-depth and exhaustive
 * search  for random  bytes including network  and disk
 * statistics,  and various pieces of system performance
 * information.
 */
BOOL RandSlowPoll(void) {
  NTSTATUS status;
  DWORD dwSize;
  BUF buf;
  PBUF bufPtr = &buf;

  /* This data is fixed for the lifetime of the process and
     hence added only once */
  static BOOL bAddedStartupInfo = FALSE;

  if (!bAddedStartupInfo) {
    STARTUPINFO startupInfo;
    startupInfo.cb = sizeof(STARTUPINFO);
    GetStartupInfo(&startupInfo);
    AddBuf(Ptr8(&startupInfo), sizeof(STARTUPINFO));
    bAddedStartupInfo = TRUE;
  }

  {
    /* Read 32 bytes from the Jitter RNG, which samples
       noise based on high-resolution CPU timing jitter */
    bufPtr->size = 32;
    BOOL collected = FALSE;

    if (jent_entropy_init() == 0) {
      /* Poll data from the Jitter RNG with osr = 1.

         According to SP 800-90B, each raw data sample consists of
         one timestamp delta, which is 64 bits long. It is assumed
         that only the least significant 4 bits of each  timestamp
         delta contains  any true entropy.  The JENT design states
         that the Jitter RNG can deliver full entropy  if and only
         if the min-entropy is at least  1/osr bit of entropy  per
         timestamp. */
      struct rand_data *collector = jent_entropy_collector_alloc(1, 0);
      if (collector) {
        ssize_t ret =
            jent_read_entropy(collector, (char *)bufPtr->bytes, bufPtr->size);
        if (ret > 0) {
          AddBuf(bufPtr->bytes, ret);
          collected = TRUE;
        }
        jent_entropy_collector_free(collector);
      }
    }

    if (!collected) {
      Log(ERR_JENT_FAILURE, FALSE, -1, __LINE__);
      return FALSE;
    }
  }

  {
    HANDLE hDevice;
    DISK_PERFORMANCE diskPerformance;
    TCHAR szDevice[32];
    int nDrive;

    /* Get disk I/O statistics for all the physical drives */
    for (nDrive = 0;; nDrive++) {
      /* Check whether this drive can be accessed */
      snprintf(szDevice, 32, _T("\\\\.\\PhysicalDrive%d"), nDrive);
      hDevice = CreateFile(szDevice, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, 0, NULL);
      if (hDevice == INVALID_HANDLE_VALUE)
        break;

      /* Query the disk statistics for the current drive.

         Note:  This only works if the user has turned on
         the disk performance counters with `diskperf -y`. */
      if (DeviceIoControl(hDevice, IOCTL_DISK_PERFORMANCE, NULL, 0,
                          &diskPerformance, sizeof(diskPerformance), &dwSize,
                          NULL))
        AddBuf(Ptr8(&diskPerformance), sizeof(DISK_PERFORMANCE));

      CloseHandle(hDevice);
    }
  }

  /* Initialize the NT kernel native API function pointers if necessary */
  if (hWinNativeApi == NULL) {
    if ((hWinNativeApi = GetModuleHandle("ntdll.dll")) != NULL) {
      if (!(pNtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)
                GetProcAddress(hWinNativeApi, "NtQuerySystemInformation"))) {
        FreeLibrary(hWinNativeApi);
        hWinNativeApi = NULL;
      }
    }
  }

  if (hWinNativeApi == NULL) {
    Log(ERR_WIN32_WINAPI, FALSE, GetLastError(), __LINE__);
    if (bStrictChecksEnabled)
      return FALSE;
  } else
  /* Query system data using the NT native API function
     NtQuerySystemInformation(), which unlike the Win32
     performance  query  API,  doesn't access  the data
     indirectly  using  pseudo-registry  keys,  and  is
     therefore much faster. */
  {
    ULONG ulSize;
    PVOID buf;

    /* We only query info for certain ID's with highly unpredictable
       data instead  of querying all  readable  information types to
       avoid  overheads for  polls  that  do not return  much usable
       randomness per-call.  Either way these ID's  alone read about
       1.4K bytes (not all useful of course) which is adequate for a
       pool size less than 1 KB. */

    /* The SYSTEM_INFORMATION_CLASS codes */
    static const uint8_t dwType[] = {
        0x02, /* SystemPerformanceInformation */
        0x08, /* SystemProcessorPerformanceInformation */
        0x17, /* SystemInterruptInformation */
        0x21, /* SystemExceptionInformation	*/
    };

    for (int i = 0; i < count(dwType); ++i) {
      /* When the  SystemInformationLength  parameter  is less than the
         size of the requested data, NtQuerySystemInformation() returns
         a  STATUS_INFO_LENGTH_MISMATCH  (0xC0000004)  error  code  and
         returns in ReturnLength the size of buffer required to receive
         the requested information. */
      status = pNtQuerySystemInformation(dwType[i], NULL, 0, &ulSize);
      if (status != 0xC0000004) {
        Log(ERR_WIN32_WINAPI, FALSE, GetLastError(), __LINE__);
        return FALSE;
      }

      /* Allocate memory for the system information */
      buf = malloc(ulSize);
      if (!buf) {
        Log(ERR_NO_MEMORY, FALSE, errno, __LINE__);
        return FALSE;
      }

      /* Recieve the system information into the allocated buffer */
      status = pNtQuerySystemInformation(dwType[i], buf, ulSize, NULL);
      if (status == ERROR_SUCCESS)
        AddBuf(Ptr8(buf), ulSize);
      else {
        free(buf);
        Log(ERR_WIN32_WINAPI, FALSE, GetLastError(), __LINE__);
        return FALSE;
      }

      free(buf);
    }
  }

  /* Initialize the IP Helper API function pointers if necessary */
  if (hIpHlpApi == NULL) {
    if ((hIpHlpApi = LoadLibrary("iphlpapi.dll")) != NULL) {
      pGetTcpStatisticsEx =
          (GETTCPSTATISTICSEX)GetProcAddress(hIpHlpApi, "GetTcpStatisticsEx");
      pGetIpStatisticsEx =
          (GETIPSTATISTICSEX)GetProcAddress(hIpHlpApi, "GetIpStatisticsEx");

      if (pGetTcpStatisticsEx == NULL || pGetIpStatisticsEx == NULL) {
        FreeLibrary(hIpHlpApi);
        hIpHlpApi = NULL;
      }
    }
  }

  if (!hIpHlpApi) {
    Log(ERR_WIN32_WINAPI, FALSE, GetLastError(), __LINE__);
    if (bStrictChecksEnabled)
      return FALSE;
  } else {
    /* Get te TCP/IP statistics for the local computer */
    MIB_TCPSTATS tcpStats;
    MIB_IPSTATS ipStats;
    if (pGetTcpStatisticsEx(&tcpStats, AF_INET) == NO_ERROR)
      AddBuf(Ptr8(&tcpStats), sizeof(MIB_TCPSTATS));
    if (pGetIpStatisticsEx(&ipStats, AF_INET) == NO_ERROR)
      AddBuf(Ptr8(&ipStats), sizeof(MIB_IPSTATS));
  }

  /* Find out whether this is an NT server or workstation if necessary */
  static BOOL isWorkstation = -1;

  if (isWorkstation == -1) {
    HKEY hKey;

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                     _T("SYSTEM\\CurrentControlSet\\Control\\ProductOptions"),
                     0, KEY_READ, &hKey) == ERROR_SUCCESS) {
      WCHAR szValue[32 + 8];
      dwSize = 32;

      isWorkstation = TRUE;
      status = RegQueryValueEx(hKey, _T("ProductType"), 0, NULL,
                               (LPBYTE)szValue, &dwSize);

      if (status == ERROR_SUCCESS && wcscmp(szValue, L"WinNT"))
        /* Note: There are (at least) three cases for ProductType:
           WinNT = NT Workstation, ServerNT = NT Server,
           LanmanNT = NT Server acting as a Domain Controller */
        isWorkstation = FALSE;

      RegCloseKey(hKey);
    }
  }

  /* Initialize the NETAPI32 function pointers if necessary */
  if (hNetApi32 == NULL) {
    if ((hNetApi32 = LoadLibrary("netapi32.dll")) != NULL) {
      pNetStatisticsGet =
          (NETSTATISTICSGET)GetProcAddress(hNetApi32, "NetStatisticsGet");
      pNetApiBufferSize =
          (NETAPIBUFFERSIZE)GetProcAddress(hNetApi32, "NetApiBufferSize");
      pNetApiBufferFree =
          (NETAPIBUFFERFREE)GetProcAddress(hNetApi32, "NetApiBufferFree");

      if (!pNetStatisticsGet || !pNetApiBufferSize || !pNetApiBufferFree) {
        FreeLibrary(hNetApi32);
        hNetApi32 = NULL;
      }
    }
  }

  if (!hNetApi32) {
    Log(ERR_WIN32_WINAPI, FALSE, GetLastError(), __LINE__);
    if (bStrictChecksEnabled)
      return FALSE;
  } else {
    /* Get Lanman Workstation/Server statistics.

       Note: Both NT Workstation and NT Server by default will be running
       both  the workstation and server services.  The heuristic below is
       probably useful though  on the assumption that the majority of the
       network traffic will be via the appropriate service. */
    LPBYTE lpBuffer;

    if (pNetStatisticsGet(
            NULL,
            (LPWSTR)(isWorkstation ? L"LanmanWorkstation" : L"LanmanServer"), 0,
            0, &lpBuffer) == 0) {
      pNetApiBufferSize(lpBuffer, &dwSize);
      AddBuf(Ptr8(lpBuffer), dwSize);
      pNetApiBufferFree(lpBuffer);
    }
  }

  /* Read data from the GPU-Z shared memory interface */
  {
    HANDLE hGPUZData;
    const GPUZ_SH_MEM *pGpuZData;

    if ((hGPUZData = OpenFileMapping(FILE_MAP_READ, FALSE, "GPUZShMem")) !=
        NULL) {
      if ((pGpuZData = (GPUZ_SH_MEM *)MapViewOfFile(hGPUZData, FILE_MAP_READ, 0,
                                                    0, 0)) != NULL) {
        if (pGpuZData->version == 1) {
          EnterCriticalSection(&randCritSec);
          AddBuf(Ptr8(pGpuZData), sizeof(GPUZ_SH_MEM));
          LeaveCriticalSection(&randCritSec);
        }
        UnmapViewOfFile(pGpuZData);
      }
      CloseHandle(hGPUZData);
    }
  }

  /* Read data from the CoreTemp shared memory interface */
  {
    HANDLE hCoreTempData;
    CORE_TEMP_SHARED_DATA *pCoreTempData;

    if ((hCoreTempData = OpenFileMapping(FILE_MAP_READ, FALSE,
                                         "CoreTempMappingObject")) != NULL) {
      if ((pCoreTempData = (CORE_TEMP_SHARED_DATA *)MapViewOfFile(
               hCoreTempData, FILE_MAP_READ, 0, 0, 0)) != NULL) {
        EnterCriticalSection(&randCritSec);
        AddBuf(Ptr8(pCoreTempData), sizeof(CORE_TEMP_SHARED_DATA));
        LeaveCriticalSection(&randCritSec);

        UnmapViewOfFile(pCoreTempData);
      }
      CloseHandle(hCoreTempData);
    }
  }

  /* Mix the pool */
  RandPoolMix();

  /* Prevent leaks */
  zeroize(bufPtr, sizeof(buf));

  return TRUE;
}

/**
 * Schematic for the pool mixing function
 * (for more info see https://vibhav950.github.io/Xrand).
 *
 *               ┌────────────────────────────────────────┐
 *            XOR│                                        │
 * ┌────────┬────▼───┬────────────────────────────────┐   │
 * │        │        │        Randomness pool         │   │
 * │________│________│________________________________│   │
 *                                                        │
 * └─────────────────────────┬────────────────────────┘   │
 *             SHA-512 digest│                            │
 *                           └────────────────────────────┘
 *                     Successive hashes
 *                     ────────────────►
 */

/**
 * The pool mixing function.  The digest of the entire pool is computed
 * using a cryptographic one-way hash function and the resulting digest
 * is added back to the pool using modulo 2^8 addition while preserving
 * its previous contents.
 *
 * Note: RNG_POOL_SIZE must be divisible by SHA512_DIGEST_LENGTH.
 */
void RandPoolMix(void) {
  if (RNG_POOL_SIZE % SHA512_DIGEST_LENGTH) {
    Throw(ERR_INVALID_POOL_SIZE, FATAL, -1, __LINE__);
  }

  uint8_t buf[SHA512_DIGEST_LENGTH];

  for (int i = 0; i < RNG_POOL_SIZE; i += SHA512_DIGEST_LENGTH) {
    /* Compute the SHA512 digest of the entire pool */
    SHA512(pRandPool, RNG_POOL_SIZE, buf);
    /* Add the resulting digest message back to the pool */
    for (int j = 0; j < SHA512_DIGEST_LENGTH; j++) {
      pRandPool[i + j] ^= buf[j];
    }
  }

  /* Prevent leaks */
  zeroize(buf, SHA512_DIGEST_LENGTH);
}

/**
 * Fetch random data to the buffer by inverting, mixing and
 * adding the contents of the randomness pool to the output
 * buffer using modulo 2^8 addition to prevent state leaks.
 */
BOOL RandFetchBytes(uint8_t *data, size_t len, int forceSlowPoll) {
  BOOL ret = FALSE;

  if (data == NULL) {
    Warn("Invalid data pointer (expected a non-NULL value)", WARN_INVALID_ARGS);
    return FALSE;
  }

  if (len < 0) {
    Warn("Invalid request length (expected a positive value)",
         WARN_INVALID_ARGS);
    return FALSE;
  }

  /* There is at max RNG_POOL_SIZE worth of entropy in the
     pool at any given instant */
  if (len > RNG_POOL_SIZE) {
    Log(ERR_REQUEST_TOO_LARGE, FALSE, -1, __LINE__);
    return FALSE;
  }

  /* This is a fatal error (triggers an immediate process termination)
     for now, but might be changed in future versions to a FALSE return */
  if (!bDidRandPoolInit)
    Throw(ERR_RAND_INIT, FATAL, GetLastError(), __LINE__);

  EnterCriticalSection(&randCritSec);

  if (!bDidSlowPoll || forceSlowPoll) {
    if (!RandSlowPoll())
      goto cleanup;
    else
      bDidSlowPoll = TRUE;
  }

  if (bUserEventsEnabled && !AddUserEvents())
    goto cleanup;

  /* Mix the pool */
  if (!RandFastPoll())
    goto cleanup;

  /* Add the current pool contents to the output buffer */
  for (int i = 0; i < len; ++i) {
    if (nCurrentPoolReadPos == RNG_POOL_SIZE)
      nCurrentPoolReadPos = 0;

    data[i] = pRandPool[nCurrentPoolReadPos];
    nCurrentPoolReadPos++;
  }

  /* Invert the pool */
  for (int i = 0; i < RNG_POOL_SIZE / sizeof(uint32_t); ++i) {
    Ptr32(pRandPool)[i] = Ptr32(pRandPool)[i] ^ 0xffffffff;
  }

  /* Mix the pool */
  if (!RandFastPoll())
    goto cleanup;

  /* Add the new pool contents to the output buffer */
  for (int i = 0; i < len; ++i) {
    if (nCurrentPoolReadPos == RNG_POOL_SIZE)
      nCurrentPoolReadPos = 0;

    data[i] ^= pRandPool[nCurrentPoolReadPos];
    nCurrentPoolReadPos++;
  }

  /* Mix the pool */
  RandPoolMix();

  ret = TRUE;

cleanup:

  LeaveCriticalSection(&randCritSec);

  return ret;
}

/**
 * Start the Random Number Generator. There can be only a
 * single active instance.
 *
 * Returns 1 if the RNG started successfully, 0 otherwise.
 */
bool RngStart(void) { return RandPoolInit(); }

/* Add randomness using user events (keystrokes and mouse movement) */
void RngEnableUserEvents(void) { bUserEventsEnabled = true; }

/* Returns 1 if the RNG is currently active, 0 otherwise. */
bool DidRngStart(void) { return bDidRandPoolInit; }

bool DidRngSlowPoll(void) { return bDidSlowPoll; }

/* Safely stop the Random Number Generator. */
void RngStop(void) { RandCleanStop(); }

/* Mix the RNG pool. */
void RngMix(void) { RandPoolMix(); }

/**
 * Request random data from the RNG.
 *
 * Returns 1 if the request was successful, 0 otherwise.
 */
bool RngFetchBytes(uint8_t *data, size_t len) {
  return RandFetchBytes(data, len, true);
}
