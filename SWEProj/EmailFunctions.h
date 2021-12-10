#pragma once

#include<iostream>
#include<io.h>   // For access().
#include<string>
#include<fstream>
#include<direct.h>
#include<windows.h>

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

void buildDns()
{
    std::string homePath = getenv("USERPROFILE");
    homePath.append("\\SWEProj");

    LPCWSTR a = L"~\\SWEProj";
    
    std::wstring temp = std::wstring(homePath.begin(), homePath.end());
    a = temp.c_str();
    CreateDirectory(a, NULL);

    std::string dnsPath = homePath + "\\dns.ps1";

    std::ofstream dnsFile;

    dnsFile.open(dnsPath);

    //Start of Powershell
    dnsFile << "param($resolutionName)" << endl;
    dnsFile << "if($resolutionName -eq $null)" << endl;
    dnsFile << "{exit}" << endl;
    dnsFile << "#Creates filepath and checks to see if it exists" << endl;
    dnsFile << "$folderPath = \"~\\SWEProj\\\"" << endl;
    dnsFile << "$fileName = $env:USERNAME + \"-Blacklist-Violation.txt\"" << endl;
    dnsFile << "$doesExist = Test-Path -Path $folderPath" << endl;
    dnsFile << "#If it does not exist then it makes the file path ~\\SWEProj\\" << endl;
    dnsFile << "if($doesExist -eq $false)" << endl;
    dnsFile << "{New-Item -Path ~ -Name \"SWEProj\" -ItemType \"directory\"}" << endl;
    dnsFile << "#Same as above, but for the file itself instead of the path" << endl;
    dnsFile << "$filePath = $folderPath + $fileName" << endl;
    dnsFile << "$doesExist = Test-Path  -Path $filePath -PathType Leaf" << endl;
    dnsFile << "#Writes the USERNAME and ipv4 address of the host computer" << endl;
    dnsFile << "if($doesExist -eq $false)" << endl;
    dnsFile << "{\"Username. . . . . . . . . . . . . : $env:USERNAME\" | Out-File -Append -FilePath $filePath" << endl;
    dnsFile << "$test = ipconfig | Select-String -Pattern 'IPv4' -SimpleMatch" << endl;
    dnsFile << "$test = $test.ToString()" << endl;
    dnsFile << "$test.substring(3) + \"`n\"| Out-File -Append -FilePath $filePath}" << endl;
    dnsFile << "#Runs the DNS resolution" << endl;
    dnsFile << "\"Violation Address\"| Out-File -Append -FilePath $filePath" << endl;
    dnsFile << "\"______________________________\"| Out-File -Append -FilePath $filePath" << endl;
    dnsFile << "Resolve-DnsName $resolutionName | Out-File -Append -FilePath $filePath" << endl;
    //End of Powershell

    dnsFile.close();
}

void buildEmail()
{
    std::string homePath = getenv("USERPROFILE");
    homePath.append("\\SWEProj");

    LPCWSTR a = L"~\\SWEProj";

    CreateDirectory(a, NULL);

    std::string emailPath = homePath + "\\email.ps1";

    std::ofstream emailFile;

    emailFile.open(emailPath);

    //Start of Powershell
    emailFile << "param($emailSwitch)" << endl;
    emailFile << "if($emailSwitch -eq $null)" << endl;
    emailFile << "{exit}" << endl;
    emailFile << "#Switch for email options" << endl;
    emailFile << "if($emailSwitch -eq 1)" << endl;
    emailFile << "{$subject = \"Blacklist Violation for \" + $env:USERNAME" << endl;
    emailFile << "$body = \"You have tried to access a blacklisted site. For Shame.\"" << endl;
    emailFile << "$attachment = \"Blacklist-Violation.txt\"}" << endl;
    emailFile << "elseif($emailSwitch -eq 2)" << endl;
    emailFile << "{$subject = \"Data Usage Notice for \" + $env:USERNAME" << endl;
    emailFile << "$body = \"This is how much data you have used!\"" << endl;
    emailFile << "$attachment = \"Blacklist-Violation.txt\"}" << endl;
    emailFile << "else" << endl;
    emailFile << "{$subject = \"Made up subject for \" + $env:USERNAME" << endl;
    emailFile << "$body = \"Someone messed up!\"" << endl;
    emailFile << "$attachment = \"Blacklist-Violation.txt\"}" << endl;
    emailFile << "$filePath = \"~\\SWEProj\\\" + $env:USERNAME + \"-\" + $attachment" << endl;
    emailFile << "#Packages Credentials for email login" << endl;
    emailFile << "$Username = \"testcat470@gmail.com \"" << endl;
    emailFile << "$Password = ConvertTo-SecureString -String \"SWEProjCSC470\" -AsPlainText -Force" << endl;
    emailFile << "$Credentials = New-Object System.Management.Automation.PSCredential $Username,$Password" << endl;
    emailFile << "#Actually sends the email" << endl;
    emailFile << "Send-MailMessage -SmtpServer smtp.gmail.com -Port 587 -UseSsl -From testcat470@gmail.com -To testcat470@gmail.com -Subject $subject -Body $body -Credential $Credentials -Attachments $filePath -Priority High -DeliveryNotificationOption OnSuccess, OnFailure" << endl;
    emailFile << "#Email: testcat470@gmail.com Password: SWEProjCSC470 \"Blacklist-Violation.txt\" \"Data-Usage.txt\"" << endl;
    //End of Powershell

    emailFile.close();
}