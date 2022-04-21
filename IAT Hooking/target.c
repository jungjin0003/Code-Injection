#include <windows.h>

#define SHOW_MESSAGEBOX 1

VOID AddButton(HWND hWnd);
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    RECT wr = { 0, 0, 500, 500};

    AdjustWindowRect(&wr, WS_OVERLAPPEDWINDOW, FALSE);

    WNDCLASSA wc = { 0, };

    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.hbrBackground = (HBRUSH)COLOR_WINDOW;
    wc.hCursor = LoadCursorA(NULL, IDC_ARROW);
    wc.hInstance = hInstance;
    wc.lpszClassName = "WindowsClass";
    wc.lpfnWndProc = WndProc;

    if (RegisterClassA(&wc) == 0)
        return -1;

    HWND hWnd = CreateWindowA("WindowsClass", "Code Injection", WS_OVERLAPPEDWINDOW | WS_VISIBLE, GetSystemMetrics(SM_CXSCREEN) / 2 - 250, GetSystemMetrics(SM_CYSCREEN) / 2 - 250, wr.right - wr.left, wr.bottom - wr.top, NULL, NULL, NULL, NULL);

    MSG msg = { 0, };

    while (GetMessageA(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    switch (Msg)
    {
    case WM_COMMAND:
        if (wParam == SHOW_MESSAGEBOX)
            MessageBoxA(hWnd, "Not Hooked..!", "Click Me!", 0);
    case WM_CREATE:
        AddButton(hWnd);
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProcA(hWnd, Msg, wParam, lParam);
    }
}

VOID AddButton(HWND hWnd)
{
    CreateWindowA("Button", "Click Me!", WS_VISIBLE | WS_CHILD, 200, 225, 100, 50, hWnd, SHOW_MESSAGEBOX, NULL, NULL);
}