using System;
using System.Net;
using System.Text;
using System.Collections.Generic;
using System.Threading;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.IO;
using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace LabMichael
{
    enum FileType
    {
        File,
        Dir
    }
    [Serializable]
    class ChangeObj
    {
        public readonly static int Size = 4096;
        FileType fileType;
        WatcherChangeTypes type;
        string path;
        int bytes;
        byte[] body;
        public ChangeObj(FileType ft, WatcherChangeTypes type, string path, byte[] body, int bts)
        {
            fileType = ft;
            this.type = type;
            this.path = path;
            this.body = body;
            bytes = bts;
        }
        public void Do()
        {
            switch (type)
            {
                case WatcherChangeTypes.Deleted:
                    Delete();
                    break;
                case WatcherChangeTypes.Created:
                    Create();
                    break;
                case WatcherChangeTypes.Changed:
                    Update();
                    break;
                case WatcherChangeTypes.Renamed:
                    Rename();
                    break;
            }
        }
        private void Delete()
        {
            if (fileType == FileType.File)
            {
                FileInfo fileInf = new FileInfo(path);
                if (fileInf.Exists)
                {
                    fileInf.Delete();
                }
            }
            else
            {
                if (Directory.Exists(path))
                    Directory.Delete(path, true);
            }
            Console.WriteLine("Info - Delete {0} {1}", (fileType == FileType.File) ? "file" : "dir", path);
        }
        private void Create()
        {
            if (fileType == FileType.File)
            {
                try
                {
                    FileStream fs = File.Create(path);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message.ToString());
                }
            }
            else
                if (!Directory.Exists(path))
                Directory.CreateDirectory(path);
            Console.WriteLine("Info - Create {0} {1}", (fileType == FileType.File) ? "file" : "dir", path);
        }
        private void Rename()
        {
            if (fileType == FileType.File)
            {
                if (File.Exists(path))
                {
                    File.Move(path, Encoding.ASCII.GetString(body, 0, bytes));
                }
            }
            else
            {
                if (Directory.Exists(path))
                    Directory.Move(path, Encoding.ASCII.GetString(body, 0, bytes));
            }
            Console.WriteLine("Info - Rename {0} {1}", (fileType == FileType.File) ? "file" : "dir", path);
        }
        private void Update()
        {
            if (fileType == FileType.File)
            {
                using (FileStream fs = File.OpenWrite(path))
                {
                    fs.Write(body, 0, bytes);
                }
                Console.WriteLine($"Info - Update file {path}");
            }
        }

    }
    class Program
    {
        static ConcurrentQueue<ChangeObj> sendQueue = new ConcurrentQueue<ChangeObj>();
        static ConcurrentQueue<ChangeObj> receiveQueue = new ConcurrentQueue<ChangeObj>();
        public static string GetLocalIPAddress()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    return ip.ToString();
                }
            }
            throw new Exception("No network adapters with an IPv4 address in the system!");
        }
        static void OnChanged(object source, FileSystemEventArgs e)
        {
            ChangeObj change = null;
            WatcherChangeTypes wct = e.ChangeType;
            switch (wct)
            {
                case WatcherChangeTypes.Created:
                case WatcherChangeTypes.Deleted:
                    change = new ChangeObj((!Directory.Exists(e.FullPath)) ? FileType.File : FileType.Dir, wct, e.FullPath, new byte[1], 0);
                    break;
                case WatcherChangeTypes.Changed:
                    if (!Directory.Exists(e.FullPath))
                    {
                        byte[] b = new byte[ChangeObj.Size];
                        int count;
                        using (FileStream fs = File.OpenRead(e.FullPath))
                        {
                            UTF8Encoding temp = new UTF8Encoding(true);
                            count = fs.Read(b, 0, ChangeObj.Size);
                        }
                        change = new ChangeObj(FileType.File, wct, e.FullPath, b, count);
                    }
                    break;
            }
            Console.WriteLine($"{e.FullPath} {wct}");
            sendQueue.Enqueue(change);
        }
        static void OnRenamed(object source, RenamedEventArgs e)
        {
            //  Show that a file has been renamed.
            WatcherChangeTypes wct = e.ChangeType;
            Console.WriteLine("{2} from {0} to {1}", e.OldFullPath, e.FullPath, wct.ToString());
            ChangeObj change = new ChangeObj((!Directory.Exists(e.FullPath)) ? FileType.File : FileType.Dir, wct, e.OldFullPath, Encoding.ASCII.GetBytes(e.FullPath), e.FullPath.Length);
            sendQueue.Enqueue(change);
        }

        static void OnError(object source, ErrorEventArgs e)
        {
            Console.WriteLine("The FileSystemWatcher has detected an error");
            if (e.GetException().GetType() == typeof(InternalBufferOverflowException))
                Console.WriteLine(("The file system watcher experienced an internal buffer overflow: " + e.GetException().Message));
        }

        static void Main(string[] args)
        {

            FileSystemWatcher fsw = new FileSystemWatcher(@"C:\Users\user\Desktop");
            fsw.NotifyFilter = NotifyFilters.LastAccess | NotifyFilters.LastWrite |
                               NotifyFilters.FileName | NotifyFilters.DirectoryName;
            fsw.Changed += new FileSystemEventHandler(OnChanged);
            fsw.Created += new FileSystemEventHandler(OnChanged);
            fsw.Deleted += new FileSystemEventHandler(OnChanged);
            fsw.Renamed += new RenamedEventHandler(OnRenamed);
            fsw.Error += new ErrorEventHandler(OnError);
            fsw.EnableRaisingEvents = true;
            fsw.IncludeSubdirectories = true;

            /*-----------------------------------------------------------------------*/

            IPEndPoint broadcast = new IPEndPoint(IPAddress.Broadcast, 80);
            List<string> ip_list = new List<string>();
            string my_ip = GetLocalIPAddress();

            int token = 1488;
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.EnableBroadcast = true;
            socket.Bind(new IPEndPoint(IPAddress.Any, 80));

            Console.WriteLine("Done - Server started");

            socket.SendTo(Encoding.ASCII.GetBytes(token.ToString(), 0, token.ToString().Length), (EndPoint)broadcast);
            Console.WriteLine($"Info - Sent to broadcast: {token.ToString()}");

            Task.Run(() => {
                int bytes = 0;
                byte[] data = new byte[5200];
                EndPoint senderRemote;
                while (true)
                {
                    senderRemote = (EndPoint)broadcast;
                    bytes = socket.ReceiveFrom(data, 0, ref senderRemote);
                    string sender_ip = ((IPEndPoint)(senderRemote)).Address.ToString();
                    string mess = Encoding.ASCII.GetString(data, 0, bytes);

                    if (sender_ip != GetLocalIPAddress())
                    {
                        Console.WriteLine($"Info - Recieve from {sender_ip} {mess.Length} bytes");
                        if (ip_list.Contains(sender_ip))
                        {
                            Regex regex = new Regex("^Change\r\n.*");
                            if (regex.IsMatch(mess))
                                receiveQueue.Enqueue(JsonSerializer.Deserialize<ChangeObj>(Encoding.ASCII.GetString(data, 8, bytes - 8)));
                        }
                        else if (mess == token.ToString())
                        {
                            Console.WriteLine($"Info - {sender_ip} token equal");
                            if (!ip_list.Contains(sender_ip))
                            {
                                Console.WriteLine($"Info - {sender_ip} saved");
                                ip_list.Add(sender_ip);
                            }
                        }

                    }
                }
            });

            Task.Run(() => {
                while (true)
                {
                    ChangeObj change;
                    while (!receiveQueue.TryDequeue(out change))
                    {
                        Thread.Sleep(2);
                    }
                    change.Do();
                }
            });
            Task.Run(() => {
                while (true)
                {
                    ChangeObj change;
                    while (!sendQueue.TryDequeue(out change))
                    {
                        Thread.Sleep(2);
                    }
                    string mess = $"Change\r\n{JsonSerializer.Serialize<ChangeObj>(change)}";
                    socket.SendTo(Encoding.ASCII.GetBytes(mess, 0, mess.Length), (EndPoint)broadcast);
                }
            });

            /*-----------------------------------------------------------------------*/
            Console.WriteLine("Press 'q' to quit the sample.");
            while (Console.Read() != 'q') ;
        }

    }
}
//C:\Users\user\Desktop