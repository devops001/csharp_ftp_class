csharp_ftp_class
================

A single file C# FTP class for you to add to your projects.

Simple usage example:
```
  var ftp       = new FTP();
  ftp.LogFile   = "ftp.log";
  ftp.Host      = "localhost";
  ftp.UserName  = "ftpuser";
  ftp.PassWord  = "ftppass";
  ftp.UseStdout = false;

  ftp.GetWorkingDir();

  ftp.Ls();

  ftp.Close();

  Console.WriteLine(ftp.SessionLog);

```
The above example set the following to the "SessionLog" field. 
It also had a "LogFile" field set, so it appended the following to that file along with timestamps:
```
220 (vsFTPd 2.2.2)
USER ftpuser
331 Please specify the password.
PASS ********
230 Login successful.
PWD
257 "/home/ftpuser"
PASV
227 Entering Passive Mode (127,0,0,1,231,23).
NLST
150 Here comes the directory listing.
226 Directory send OK.
QUIT
221 Goodbye.
```
Class description:
```
  // public fields:

  public string PassWord   (set)
  public string ErrorMsg   (get)
  public string SystemType (get)
  public string Host       (get,set)
  public int    Port       (get,set) 
  public string UserName   (get,set) 
  public string LogFile    (get,set) 
  public int    RetryCount (get,set) 
  public bool   UseStdout  (get,set) 
  public string SessionLog (get,set)

  // public methods:

  public FTP()
  public void ClearSessionLog()
  public string Dir()
  public string Dir(string fileName)
  public string Ls()
  public string GetWorkingDir()
  public string GetSystemType()
  public long GetFileSize(string remoteFilePath)
  public bool GetFile(string remoteFilePath, string localFilePath)
  public bool GetFiles(string regularExpression, string localDirectory)
  public bool PutFile(string localFilePath, string remoteFilePath)
  public bool PutFiles(string regularExpression, string localDirectory)
  public bool DeleteFile(string filePath)
  public bool DeleteFiles(string regularExpression)
  public bool DeleteDirectory(string directoryPath)
  public bool CreateDirectory(string directoryPath)
  public bool ChangeWorkingDir(string dir)
  public bool Binary()
  public bool Ascii()
  public bool Ebcdic()
  public void Close()
  public static void EnableDebug()
  public static void DisableDebug()
```

