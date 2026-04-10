#include <iostream>
#include <windows.h>

using namespace std;

int main() {
    cout << "----------------------------------------" << endl;
    LPCSTR rawCmdLine = GetCommandLineA();
    
    cout << "[Target] My Raw Command Line String is: " << endl;
    cout << rawCmdLine << endl;
    
    cout << "----------------------------------------" << endl;
    return 0;
}