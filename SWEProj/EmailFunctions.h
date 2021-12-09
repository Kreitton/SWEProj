#pragma once

#include<iostream>
#include <io.h>   // For access().
#include <string>

using namespace std;

// Runs dns.ps1 powershell script
// testAddress is the ipv4, ipv6, or hostname to be resolved
void resolveAddress(std::string testAddress)
{
    std::string homePath = getenv("USERPROFILE");
    std::string strPath = homePath + "\\dns.ps1";

    testAddress = " " + testAddress;

    std::string cmd("start powershell.exe ~\\dns.ps1");
    cmd += testAddress;

    //I was getting security problems so I have been playing with this part. I am not sure what the correct answer is, but this works right now
    if (access(strPath.c_str(), 0) == 0)
    {
        //system("start powershell.exe Set-ExecutionPolicy RemoteSigned \n");
        system(cmd.c_str());
        system("cls");
    }
    else
    {
        system("cls");
        cout << "File does not exist\n";
        system("pause");
    }
}

// Runs email.ps1 powershell script
// Subject: 1 (Blacklist) or 2 (Data)
void sendEmail(std::string emailTopic)
{
    std::string homePath = getenv("USERPROFILE");
    std::string cmd = ("start powershell.exe ~\\email.ps1 ");

    cmd += emailTopic;
    homePath = getenv("USERPROFILE");

    std::string strPath = homePath + "\\email.ps1";

    //I was getting security problems so I have been playing with this part. I am not sure what the correct answer is, but this works right now
    if (access(strPath.c_str(), 0) == 0)
    {
        //system("start powershell.exe Set-ExecutionPolicy RemoteSigned \n");
        system(cmd.c_str());
        //system("cls");
    }
    else
    {
        system("cls");
        cout << "File does not exist\n";
        system("pause");
    }
}