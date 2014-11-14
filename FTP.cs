/* Author: devops001@gmail.com
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Text;
using System.Net.Sockets;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;

namespace FTPLib {

    public class FileDoesNotExistException : Exception {
        public FileDoesNotExistException(string msg) : base(msg) {
        }
    }

    public class FTP {

        // static variables:
        private static bool isDebugging = false;
        private static int BLOCK_SIZE   = 512;
        private static Encoding ASCII   = Encoding.ASCII;
        private static Dictionary<string, int[]> ExpectedReturnCodes = new Dictionary<string, int[]>();

        // static constructor:
        static FTP() {
            ExpectedReturnCodes.Add("USER", new int[] { 331 });            // send username
            ExpectedReturnCodes.Add("PASS", new int[] { 230 });            // send password
            ExpectedReturnCodes.Add("PASV", new int[] { 227 });            // set passive mode
            ExpectedReturnCodes.Add("TYPE", new int[] { 200 });            // set ascii, binary, or ebcdic
            ExpectedReturnCodes.Add("PWD",  new int[] { 257 });            // print working dir
            ExpectedReturnCodes.Add("CWD",  new int[] { 250 });            // change working dir
            ExpectedReturnCodes.Add("FEAT", new int[] { 211 });            // list features
            ExpectedReturnCodes.Add("HELP", new int[] { 214 });            // list help
            ExpectedReturnCodes.Add("DELE", new int[] { 250 });            // delete
            ExpectedReturnCodes.Add("SIZE", new int[] { 213 });            // get file size in bytes
            ExpectedReturnCodes.Add("QUIT", new int[] { 221 });            // close connection
            ExpectedReturnCodes.Add("NLST", new int[] { 125, 150, 226 });  // ls
            ExpectedReturnCodes.Add("RETR", new int[] { 125, 150, 226 });  // get
            ExpectedReturnCodes.Add("STOR", new int[] { 125, 150, 226 });  // put
            ExpectedReturnCodes.Add("LIST", new int[] { 125, 150, 226 });  // dir
            ExpectedReturnCodes.Add("SYST", new int[] { 215 });            // system type (Unix, Windows, etc)
            ExpectedReturnCodes.Add("RMD",  new int[] { 250 });            // remove directory
            ExpectedReturnCodes.Add("MKD",  new int[] { 250, 257 });       // create directory
        }

        // instance variables
        private string host;
        private string username;
        private string password;
        private int port;
        private Socket commandSocket;
        private Socket dataSocket;
        private Byte[] buffer;
        private int retValue;
        private string retText;
        private List<string> sessionLog;
        private string logFilePath;
        private bool connected;
        private bool streaming;
        private string errorMsg;
        private string systemType;
        private int retryCount;
        private bool useStdout;
        private bool parmsAreValid;

        // instance constructor:
        public FTP() {
            host          = "";
            username      = "";
            password      = "";
            port          = 21;
            buffer        = new Byte[BLOCK_SIZE];
            connected     = false;
            streaming     = false;
            sessionLog    = new List<string>();
            logFilePath   = "";
            errorMsg      = "";
            systemType    = "unkown";
            retryCount    = 0;
            useStdout     = true;
            parmsAreValid = false;
        }

        // accessors
        public string PassWord   { set { password = value;   } }
        public string ErrorMsg   { get { return errorMsg;    } }
        public string Host       { get { return host;        } set { host        = value; } }
        public int Port          { get { return port;        } set { port        = value; } }
        public string UserName   { get { return username;    } set { username    = value; } }
        public string LogFile    { get { return logFilePath; } set { logFilePath = value; } }
        public int    RetryCount { get { return retryCount;  } set { retryCount  = value; } }
        public bool   UseStdout  { get { return useStdout;   } set { useStdout   = value; } }
        public string SystemType { get { return systemType;  } }
        public string SessionLog {
            get {
                StringBuilder lines = new StringBuilder();
                foreach (string line in sessionLog) {
                    lines.Append(line);
                }
                return lines.ToString();
            }
        }

        // public methods:

        public void ClearSessionLog() {
            sessionLog.Clear();
        }

        public string Dir() {
            openDataSocket();
            sendCommand("LIST");

            // receive data:
            var listing = new StringBuilder();
            int bytes   = 0;
            while (true) {
                try {
                    bytes = dataSocket.Receive(buffer, buffer.Length, 0);
                    listing.Append(ASCII.GetString(buffer, 0, bytes));
                    if (bytes <= 0) {
                        break;
                    }
                } catch (SocketException se) {
                    error("Caught socket error: "+ se.Source +": "+ se.Message);
                    if (shouldRetry()) {
                        listing.Append(Dir());
                    } else {
                        abend("unrecoverable socket error while attempting Dir()", 99);
                    }
                }
            }
            closeDataSocket();
            parseReply();
            return listing.ToString();
        }

        public string Dir(string fileName) {
            openDataSocket();
            sendCommand("LIST "+ fileName);

            // receive data:
            var listing = new StringBuilder();
            int bytes   = 0;
            while (true) {
                try {
                    bytes = dataSocket.Receive(buffer, buffer.Length, 0);
                    listing.Append(ASCII.GetString(buffer, 0, bytes));
                    if (bytes <= 0) {
                        break;
                    }
                } catch (SocketException se) {
                    error("Caught socket error: "+ se.Source +": "+ se.Message);
                    if (shouldRetry()) {
                        listing.Append(Dir(fileName));
                    } else {
                        error("socket error: "+ se.Message);
                        abend("unrecoverable socket error while attempting Dir("+ fileName +")", 99);
                    }
                }
            }
            closeDataSocket();
            parseReply();
            return listing.ToString();
        }

        public string Ls() {
            openDataSocket();
            sendCommand("NLST");

            // receive data:
            var listing = new StringBuilder();
            int bytes   = 0;
            while (true) {
                try {
                    bytes = dataSocket.Receive(buffer, buffer.Length, 0);
                    listing.Append(ASCII.GetString(buffer, 0, bytes));
                    if (bytes <= 0) {
                        break;
                    }
                } catch (SocketException se) {
                    error("Caught socket error: "+ se.Source +": "+ se.Message);
                    if (shouldRetry()) {
                        listing.Append(Ls());
                    } else {
                        abend("unrecoverable socket error while attempting Ls()", 99);
                    }
                }
            }
            closeDataSocket();
            parseReply();
            return listing.ToString();
        }

        public string GetWorkingDir() {
            sendCommand("PWD");
            var match = Regex.Match(retText, @"^(.*) is current directory\.$"); //<- windows...
            if (match.Success) {
                return match.Groups[1].Value;
            } else {
                return retText;
            }
        }

        public string GetSystemType() {
            sendCommand("SYST");
            systemType = retText;
            return systemType;
        }

        // throws FileDoesNotExistException:
        public long GetFileSize(string remoteFilePath) {
            long size = 0;
            if (sendCommand("SIZE " + remoteFilePath)) {
                size = Int32.Parse(retText);
            } else {
                string msg = "remote file does not exist: "+ remoteFilePath;
                error(msg);
                throw new FileDoesNotExistException(msg);
            }

            // check command socket:
            //parseReply();

            return size;
        }

        // throws FileDoesNotExistException:
        public bool GetFile(string remoteFilePath, string localFilePath) {
            // make sure the remote file exists before doing anything else:
            long remoteFileSize = GetFileSize(remoteFilePath);  //<- throws FileDoesNotExistException

            bool isOK = true;
            String remoteDirName  = Path.GetDirectoryName(remoteFilePath);
            String remoteFileName = Path.GetFileName(remoteFilePath);
            String localDirName   = Path.GetDirectoryName(localFilePath);
            String localFileName  = Path.GetFileName(localFilePath);

            if (String.IsNullOrEmpty(localDirName)) {
                localDirName = ".";
            }

            // verify that localDir exists:
            if (!Directory.Exists(localDirName)) {
                try {
                    Directory.CreateDirectory(localDirName);
                } catch (Exception dirException) {
                    isOK = false;
                    error("Could not create local dir: \""+ localDirName +"\" error: "+ dirException.Message);
                }
            }

            // create the empty localFile:
            if (!File.Exists(localFilePath)) {
                try {
                    Stream file = File.Create(localFilePath);
                    file.Close();
                } catch (Exception fileException) {
                    error("Could not create local file: \""+ localFilePath +"\" error: "+ fileException.Message);
                    return false;
                }
            }

            long transferredBytes = 0;

            // open a local stream and fill it with the remote file's contents:
            using (var fileStream = new FileStream(localFilePath, FileMode.Open)) {
                openDataSocket();
                if (sendCommand("RETR " + remoteFilePath)) {
                    while (transferredBytes < remoteFileSize) {
                        //int bytes = dataSocket.Receive(buffer, buffer.Length, 0);
                        int bytes = dataSocket.Receive(buffer);
                        transferredBytes += bytes;
                        fileStream.Write(buffer, 0, bytes);
                        if (bytes <= 0) {
                            break;
                        }
                    }
                }
                closeDataSocket();
            }

            // compare file size to bytes transferred:
            if (remoteFileSize != transferredBytes) {
                error("Transferred \"" + transferredBytes + "\" bytes instead of expected \"" + remoteFileSize + "\"");
                log("Removing the incomplete local file: "+ localFilePath);
                File.Delete(localFilePath);
                isOK = false;
            }

            // check the command socket:
            parseReply();

            return isOK;
        }

        // throws FileDoesNotExistException:
        public bool GetFiles(string regularExpression, string localDirectory) {
            bool isOK = true;
            Regex regex = new Regex(regularExpression);
            List<string> files = new List<string>();

            // iterate through the directory listing and grab all file names:
            foreach (string file in Ls().Split(new char[] { '\r', '\n' })) {
                if (file != null && !file.Equals("")) {
                    debug("checking if file: <" + file + "> matches: <" + regularExpression + ">");
                    if (regex.IsMatch(file)) {
                        files.Add(file);
                        debug("file: <" + file + "> matches.");
                    } else {
                        debug("file: <" + file + "> does not match.");
                    }
                }
            }

            // iterate through found files and get them:
            foreach (string file in files) {
                string remoteFile = Regex.Replace(file, "\r", "");
                string localFile  = Path.Combine(localDirectory, remoteFile);
                log("Found remote file: " + remoteFile);
                log("Saving to:         " + localFile);
                if (isOK) {
                    if (!GetFile(remoteFile, localFile)) {
                        isOK = false;
                    }
                }
            }

            // log something if no files were found:
            if (files.Count < 1) {
                error("No files were found to get with file mask: \"" + regularExpression + "\"");
                isOK = false;
            }
            return isOK;
        }

        // throws FileDoesNotExistException:
        public bool PutFile(string localFilePath, string remoteFilePath) {
            bool isOK = true;

            // verify that localFilePath exists:
            if (!File.Exists(localFilePath)) {
                string msg = "local file does not exist: "+ localFilePath;
                error(msg);
                throw new FileDoesNotExistException(msg);
            }

            if (isOK) {
                // start transfer:
                openDataSocket();
                if (sendCommand("STOR " + remoteFilePath)) {
                    // open stream to read localFilePath:
                    FileStream fileStream = new FileStream(localFilePath, FileMode.Open, FileAccess.Read);
                    // send data:
                    int bytes;
                    while ((bytes = fileStream.Read(buffer, 0, buffer.Length)) > 0) {
                        try {
                            dataSocket.Send(buffer, bytes, 0);
                        } catch (SocketException se) {
                            error("Caught socket error: "+ se.Source +": "+ se.Message);
                            if (shouldRetry()) {
                                isOK = PutFile(localFilePath, remoteFilePath);
                            } else {
                                isOK = false;
                            }   
                        }
                    }
                    // close file stream:
                    fileStream.Close();
                } else {
                    isOK = false;
                }
                // close the data socket:
                closeDataSocket();
                // check the command socket:
                parseReply();
            }
            return isOK;
        }

        // throws FileDoesNotExistException:
        public bool PutFiles(string regularExpression, string localDirectory) {
            bool isOK   = true;
            Regex regex = new Regex(regularExpression);
            var files   = new List<string>();

            // iterate through the local directory and grab all file names:
            foreach (string file in Directory.GetFiles(localDirectory)) {
                String baseName = Path.GetFileName(file);
                if (baseName != null && !baseName.Equals("")) {
                    debug("checking if file: <" + baseName + "> matches: <" + regularExpression + ">");
                    if (regex.IsMatch(baseName)) {
                        files.Add(baseName);
                        debug("file: <" + baseName + "> matches.");
                    } else {
                        debug("file: <" + baseName + "> does not match.");
                    }
                }
            }

            foreach (string file in files) {
                string localFile  = Path.Combine(localDirectory, file);
                string remoteFile = Path.GetFileName(file);
                log("Found local file: " + localFile);
                log("Sending to:       " + remoteFile);

                if (isOK) {
                    isOK = PutFile(localFile, remoteFile);
                }
            }

            // log something if no files were found:
            if (files.Count < 1) {
                error("No files were found to put with file mask: \"" + regularExpression + "\"");
                isOK = false;
            }

            return isOK;
        }

        public bool DeleteFile(string filePath) {
            return sendCommand("DELE " + filePath);
        }

        public bool DeleteFiles(string regularExpression) {
            bool isOK   = true;
            Regex regex = new Regex(regularExpression);
            List<string> files = new List<string>();

            // iterate through the directory listing and grab all file names:
            foreach (string file in Ls().Split(new char[] { '\r', '\n' })) {
                if (regex.IsMatch(file)) {
                    files.Add(file);
                }
            }

            // iterate through found files and delete them:
            foreach (string file in files) {
                string remoteFile = Regex.Replace(file, "\r", "");
                log("Found remote file to delete: " + remoteFile);
                if (!DeleteFile(remoteFile)) {
                    isOK = false;
                }
            }

            // log something if no files were found:
            if (files.Count < 1) {
                error("No files were found to delete with file mask: \"" + regularExpression + "\"");
                isOK = false;
            }
            return isOK;
        }

        public bool DeleteDirectory(string directoryPath) {
            return sendCommand("RMD " + directoryPath);
        }

        public bool CreateDirectory(string directoryPath) {
            return sendCommand("MKD " + directoryPath);
        }

        public bool ChangeWorkingDir(string dir) {
            return sendCommand("CWD " + dir);
        }

        public bool Binary() {
            return sendCommand("TYPE I");
        }

        public bool Ascii() {
            return sendCommand("TYPE A");
        }

        public bool Ebcdic() {
            return sendCommand("TYPE E");
        }

        public void Close() {
            sendCommand("QUIT");
            commandSocket.Close();
            connected = false;
        }

        public static void EnableDebug() {
            isDebugging = true;
        }

        public static void DisableDebug() {
            isDebugging = false;
        }

        // private (helper) methods:

        private bool login() {
            bool isOK = true;

            if (connected == true && !isSocketConnected(commandSocket)) {
                connected = false;
                clearCommandChannel();
            }

            if (!connected) {
                if (validateParameters()) {
                    commandSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    commandSocket.Connect(new IPEndPoint(Dns.GetHostEntry(host).AddressList[0], port));
                    if (commandSocket.Connected) {
                        log("Connected to port " + port + " on " + host);
                        parseReply();
                        connected = true;
                        if ((sendCommand("USER " + username) && (sendCommand("PASS " + password)))) {
                            if (systemType == "unknown") {
                                GetSystemType();
                            }
                        } else {
                            error("Failed to login");
                            isOK = false;
                        }
                    } else {
                        error("Failed to connect to port" + port + " on " + host);
                        isOK = false;
                    }
                } else {
                    isOK = false;
                }
            }
            return isOK;
        }

        private bool openDataSocket() {
            bool isOK = true;
            if (login()) {
                if (streaming) {
                    closeDataSocket();
                }
                if (sendCommand("PASV")) {
                    streaming = true;

                    // PASV should return something like this:
                    // Entering Passive Mode (67,18,89,251,24,214)

                    // parse the PASV return text to grab the port numbers:
                    int front       = retText.IndexOf('(');
                    int back        = retText.IndexOf(')');
                    string[] pieces = retText.Substring(front + 1, back - front - 1).Split(',');

                    // The "<< 8" does 8 bit shifts to the left on the port number returned. 
                    // See "bit shifts" here: http://en.wikipedia.org/wiki/Bitwise_operation
                    int dataPort = (Int32.Parse(pieces[4]) << 8) + Int32.Parse(pieces[5]);
                    dataSocket   = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    dataSocket.Connect(new IPEndPoint(Dns.GetHostEntry(host).AddressList[0], dataPort));
                    isOK = dataSocket.Connected;
                } else {
                    isOK = false;
                }
            } else {
                isOK = false;
            }
            return isOK;
        }

        private void closeDataSocket() {
            dataSocket.Close();
            streaming = false;
        }

        private bool sendCommand(String command) {
            bool isOK = true;
            if (login()) {
                addToSessionLog(command);
                debug("sending command:  " + command);
                Byte[] cmdBytes = Encoding.ASCII.GetBytes((command + "\r\n").ToCharArray());
                try {
                    commandSocket.Send(cmdBytes, cmdBytes.Length, 0);
                    parseReply();
                } catch (SocketException se) {
                    error("Caught socket error in sendCommand: "+ se.Source +": "+ se.Message);
                    if (shouldRetry()) {      
                        int sleepMinutes = 3;
                        log("Sleeping for "+ sleepMinutes +" minutes before retrying.");
                        System.Threading.Thread.Sleep(sleepMinutes * 60 * 1000);
                        connected = false;
                        debug("connected=false; calling closeDataSocket()");
                        closeDataSocket();
                        debug("calling openDataSocket()");
                        openDataSocket();;
                        debug("calling sendCommand again");
                        sendCommand(command);
                    } else {
                        log("no more retries, abending from above socket error");
                        throw se;
                    }
                }

                // grab the ftp command with out the parm(s):
                string ftpCommand = command.Split(' ')[0];

                // create a string array of the expected return codes:
                // this will be used in the error message. We have to convert the int[] to
                // a string[] so we can call String.Join on it.
                string[] expectedReturnCodes = new string[ExpectedReturnCodes[ftpCommand].Length];

                // iterate through expected codes to compare with retValue:
                bool goodReturnCode = false;
                for (int i = 0; i < expectedReturnCodes.Length; i++) {
                    // again, for the error message:
                    expectedReturnCodes[i] = ExpectedReturnCodes[ftpCommand][i].ToString();
                    if (retValue == ExpectedReturnCodes[ftpCommand][i]) {
                        goodReturnCode = true;
                    }
                }

                // write error message if bad return code:
                if (!goodReturnCode) {
                    string codes = String.Join(", ", expectedReturnCodes);
                    string msg = "Expected " + codes + " from \""+ command +"\" but got: " + retValue;
                    error(msg);
                    isOK = false;
                }
            }
            return isOK;
        }

        private string getReply() {
            string reply;
            // remember where we're at in the session log:
            int index      = sessionLog.Count;
            var thisOutput = new List<string>();
            int bytes      = 0;
            while (true) {
                try {
                    bytes = commandSocket.Receive(buffer, buffer.Length, 0);
                } catch (SocketException se) {
                    error("Caught socket error in getReply(): "+ se.Source +": "+ se.Message);
                    throw se;
                }
                reply = ASCII.GetString(buffer, 0, bytes);
                thisOutput.Add(reply);
                if (bytes < buffer.Length) {
                    break;
                }
            }
            // add this output to the session log:
            foreach (string line in thisOutput) {
                string chomped = Regex.Replace(line, "\n", "");
                chomped        = Regex.Replace(chomped, "\r", "");
                addToSessionLog(chomped);
            }
            // set retText to the output from this command only:
            retText = String.Join(Environment.NewLine, thisOutput.ToArray());

            // split up the data into lines:
            string[] lines = reply.Split('\n');

            // If we get 2 lines, then assume text on first and blank second
            // If we get > 2 lines, then grab 2nd to last (and should have a blank last line)
            // If we get < 2 lines, then grab whatever is there
            if (lines.Length > 2) {
                // grab 2nd to last:
                reply = lines[lines.Length - 2];
            } else {
                reply = lines[0];
            }

            // The first 3 characters should be the retValue, the 4th a space
            // otherwise we need to keep going
            if (!reply.Substring(3, 1).Equals(" ")) {
                return getReply();
            }

            // reply should look something like this: 
            // 230 Login successful.
            return reply;
        }
        
        private void parseReply() {
            retValue = 0;
            retText = "";
            // reply will look something like this:
            // 230 Login successful.
            string reply = getReply();

            // split it up:
            retValue    = Int32.Parse(reply.Substring(0, 3));
            string text = reply.Substring(4, reply.Length - 5);

            // remove double quotes (sometimes around directories):
            retText = Regex.Replace(text, "\"", "");

            debug("parseReply retText:  " + retText);
            debug("parseReply retValue: " + retValue);
        }

        private bool validateParameters() {
            if (!parmsAreValid) {
                parmsAreValid = true;
                if (!(host.Length > 0 && username.Length > 0 && password.Length > 0)) {
                    error("Missing one or more required FTP parameters (host, username, password)");
                    parmsAreValid = false;
                }
            }
            return parmsAreValid;
        }

        private void addToSessionLog(string line) {
            string msg = line;
            if (Regex.IsMatch(msg, @"^PASS")) {
                msg = "PASS ********";
            }
            sessionLog.Add(msg + Environment.NewLine);
            log(msg);
        }

        private void log(string msg) {
            if (logFilePath != "") {
                // filter passwords:
                if (Regex.IsMatch(msg, @"^PASS")) {
                    msg = "PASS ********";
                }
                FileStream stream   = new FileStream(logFilePath, FileMode.Append, FileAccess.Write);
                StreamWriter writer = new StreamWriter(stream);
                string timestamp    = getTimestamp();
                writer.WriteLine(timestamp + " FTP " + msg);
                writer.Close();
            }
            if (useStdout) {
                Console.WriteLine(msg);
            }
        }

        private string getTimestamp() {
            return String.Format("{0:yyyyMMdd.HHmm.ss}", DateTime.Now);
        }

        private void error(string msg) {
            errorMsg = msg;
            log("ERROR: "+ msg);
        }

        private void debug(string msg) {
            if (isDebugging) {
                log("DEBUG: "+ msg);
            }
        }

        private void abend(string msg, int rc) {
            log("ABEND: "+ msg);
            Environment.Exit(rc);
        }

        private bool shouldRetry() {
            if (retryCount > 0) {
                retryCount -= 1;
                log("Retrying connection. RetryCount is now: "+ retryCount);
                return true;
            } else {
                log("RetryCount is zero. Try setting higher to retry this connection again.");
                return false;
            }
        }

        private bool isSocketConnected(Socket s) {
            bool part1 = s.Poll(1000, SelectMode.SelectRead);
            bool part2 = (s.Available == 0);
            if (part1 & part2) {
                return false;
            } else {
                return true;
            }
        }


        private void clearCommandChannel() {
            int bytes;
            while (true) {
                try {
                    bytes = commandSocket.Receive(buffer, buffer.Length, 0);
                } catch (Exception e) {
                    bytes = 0;
                }
                if (bytes < buffer.Length) {
                    break;
                }
            }
            buffer = new Byte[BLOCK_SIZE];
        }


    }
}

