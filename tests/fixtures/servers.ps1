# TB-287 fixture: loopback servers for the network module's own test runner.
#
# What it starts, all on 127.0.0.1:
#   * TLS servers from openssl (secure, wrong-name, expired, rogue CA, and the
#     fixed 443/8443 pair when those ports are free). openssl is used because
#     .NET Framework's SslStream cannot serve a certificate generated at runtime:
#     a Pfx import on Windows 10+ always yields a CNG key, and SslStream then
#     refuses it with "The server mode SSL must use a certificate with the
#     associated private key" (the .NET side of the TB-282 SEC_E_NO_CREDENTIALS
#     finding). openssl keeps its keys in files under the work directory, so NOT
#     ONE key container is created and no certificate store is touched.
#   * a plaintext recorder that answers X-Transport: plain and can send a slow
#     chunked body for the streaming test.
#   * SOCKS5 proxies: no-auth, user/pass, one per reply code, one that refuses
#     every auth method, one that hangs up, and one that never answers.
#
# KEY STORE: nothing. That is the point of the openssl switch, and it is asserted
# by tests/run_all.ps1, which fails if a fixture key ledger it expects to be
# absent ever appears.
#
# Usage: powershell -NoProfile -File servers.ps1 -Work <dir> -Info <info.json>
# It writes <info.json>, prints READY, and exits when <dir>/stop appears.

param(
    [Parameter(Mandatory = $true)][string]$Work,
    [Parameter(Mandatory = $true)][string]$Info,
    [string]$OpenSsl = ''
)

$ErrorActionPreference = 'Stop'
$prefix = "tb287-fixture-$PID"
$children = New-Object System.Collections.ArrayList    # openssl s_server processes
$owned = New-Object System.Collections.ArrayList      # in-process servers and proxies

function Find-OpenSsl {
    param([string]$Hint)
    if ($Hint -ne '') { return $Hint }
    foreach ($candidate in @('C:\msys64\mingw64\bin\openssl.exe', 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe')) {
        if (Test-Path $candidate) { return $candidate }
    }
    $found = Get-Command openssl.exe -ErrorAction SilentlyContinue
    if ($found) { return $found.Source }
    throw 'openssl.exe not found: pass -OpenSsl <path> (the TLS test servers need it)'
}

$openssl = Find-OpenSsl -Hint $OpenSsl
$workFull = (New-Item -ItemType Directory -Force -Path $Work).FullName

# ---- certificates (files only) ---------------------------------------------

function Invoke-OpenSsl {
    param([string[]]$Arguments)
    # openssl writes its key-generation progress to stderr, and with
    # $ErrorActionPreference = Stop a native stderr line becomes a terminating
    # error even when it is redirected. The preference is lowered for the call.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $log = Join-Path $workFull 'openssl.log'
    try {
        & $openssl @Arguments 2>> $log | Out-Null
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    if ($code -ne 0) {
        throw ('openssl ' + ($Arguments -join ' ') + ' failed: ' + (Get-Content -Raw -LiteralPath $log))
    }
}

function New-CertificateAuthority {
    param([string]$Name)
    Invoke-OpenSsl @('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '3650',
        '-keyout', (Join-Path $workFull ($Name + '.key')), '-out', (Join-Path $workFull ($Name + '.pem')),
        '-subj', ('/CN=' + $prefix + '-' + $Name), '-addext', 'basicConstraints=critical,CA:TRUE',
        '-addext', 'keyUsage=critical,keyCertSign,cRLSign') | Out-Null
    return [pscustomobject]@{
        Cert = Join-Path $workFull ($Name + '.pem')
        Key = Join-Path $workFull ($Name + '.key')
    }
}

function New-Leaf {
    param([string]$Name, [string]$Subject, [string]$San, $Issuer, [int]$Days = 30)
    $key = Join-Path $workFull ($Name + '.key')
    $csr = Join-Path $workFull ($Name + '.csr')
    $cert = Join-Path $workFull ($Name + '.pem')
    $ext = Join-Path $workFull ($Name + '.ext')
    Invoke-OpenSsl @('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256',
        '-keyout', $key, '-out', $csr, '-subj', ('/CN=' + $Subject)) | Out-Null
    $lines = @(
        'basicConstraints=CA:FALSE'
        'keyUsage=digitalSignature,keyEncipherment'
        'extendedKeyUsage=serverAuth'
    )
    if ($San -ne '') { $lines += ('subjectAltName=' + $San) }
    Set-Content -LiteralPath $ext -Value $lines -Encoding ASCII
    # -days 0 makes notAfter == notBefore, which is already invalid on arrival:
    # that is the expired-certificate case.
    Invoke-OpenSsl @('x509', '-req', '-in', $csr, '-CA', $Issuer.Cert, '-CAkey', $Issuer.Key,
        '-CAcreateserial', '-out', $cert, '-days', "$Days", '-sha256', '-extfile', $ext) | Out-Null
    return [pscustomobject]@{ Cert = $cert; Key = $key }
}

$ca = New-CertificateAuthority -Name 'ca'
$rogueCa = New-CertificateAuthority -Name 'rogue-ca'
# Certificate objects and server ports must not share names: PowerShell variables
# are case-insensitive, so $wrongName and $wrongname would be the same variable.
$leafLocalhost = New-Leaf -Name 'leaf-localhost' -Subject 'localhost' -San 'DNS:localhost,IP:127.0.0.1' -Issuer $ca
$leafWrong = New-Leaf -Name 'leaf-wrong' -Subject 'wrong.example' -San 'DNS:wrong.example' -Issuer $ca
$leafExpired = New-Leaf -Name 'leaf-expired' -Subject 'localhost' -San 'DNS:localhost,IP:127.0.0.1' -Issuer $ca -Days 0
$leafRogue = New-Leaf -Name 'leaf-rogue' -Subject 'localhost' -San 'DNS:localhost,IP:127.0.0.1' -Issuer $rogueCa

# ---- TLS servers (openssl s_server children) --------------------------------

function Get-FreePort {
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    $listener.Stop()
    return $port
}

function Start-TlsServer {
    param([string]$Role, [int]$Port, $Certificate)
    $arguments = @('s_server', '-accept', "$Port", '-cert', $Certificate.Cert, '-key', $Certificate.Key,
        '-tls1_2', '-www', '-naccept', '2000', '-quiet')
    $process = Start-Process -FilePath $openssl -ArgumentList $arguments -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $workFull ($Role + '.tls.out')) `
        -RedirectStandardError (Join-Path $workFull ($Role + '.tls.err'))
    [void]$children.Add([pscustomobject]@{ Role = $Role; Process = $process })
    # Wait until it accepts, so the test never races the listener.
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline) {
        if ($process.HasExited) {
            $why = Get-Content -Raw -LiteralPath (Join-Path $workFull ($Role + '.tls.err'))
            throw ("openssl s_server for " + $Role + " exited: " + $why)
        }
        $probe = New-Object System.Net.Sockets.TcpClient
        try { $probe.Connect('127.0.0.1', $Port); $probe.Close(); return $Port }
        catch { try { $probe.Close() } catch { }; Start-Sleep -Milliseconds 100 }
    }
    throw ("openssl s_server for " + $Role + " never listened on " + $Port)
}

function Test-PortFree {
    param([int]$Port)
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Port)
    try { $listener.Start(); return $true } catch { return $false } finally { try { $listener.Stop() } catch { } }
}

# ---- plaintext recorder and SOCKS5 proxies (in this process) ----------------

$code = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

public static class Tb287
{
    public sealed class Recorder : IDisposable
    {
        readonly TcpListener listener;
        readonly Thread thread;
        readonly string role;
        volatile bool stopping;
        public int Port { get; private set; }
        public long Connections;

        public Recorder(string role, int port)
        {
            this.role = role;
            listener = new TcpListener(IPAddress.Parse("127.0.0.1"), port);
            listener.Start();
            Port = ((IPEndPoint)listener.LocalEndpoint).Port;
            thread = new Thread(Loop) { IsBackground = true, Name = role };
            thread.Start();
        }

        void Loop()
        {
            while (!stopping)
            {
                TcpClient client;
                try { client = listener.AcceptTcpClient(); }
                catch { return; }
                Interlocked.Increment(ref Connections);
                ThreadPool.QueueUserWorkItem(_ => Handle(client));
            }
        }

        void Handle(TcpClient client)
        {
            try
            {
                client.ReceiveTimeout = 8000;
                client.SendTimeout = 8000;
                var stream = client.GetStream();
                string request = ReadHeaders(stream);
                string path = FirstToken(request);
                string head = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                    + "X-Transport: plain\r\nX-Role: " + role + "\r\n";
                if (path.StartsWith("/stream"))
                {
                    // A slow chunked body: on_chunk must see several chunks, in order.
                    string[] pieces = { "alpha ", "beta ", "gamma ", "omega" };
                    head += "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
                    byte[] header = Encoding.ASCII.GetBytes(head);
                    stream.Write(header, 0, header.Length);
                    foreach (string piece in pieces)
                    {
                        byte[] chunk = Encoding.UTF8.GetBytes(piece);
                        string size = chunk.Length.ToString("x") + "\r\n";
                        byte[] sizeBytes = Encoding.ASCII.GetBytes(size);
                        stream.Write(sizeBytes, 0, sizeBytes.Length);
                        stream.Write(chunk, 0, chunk.Length);
                        stream.WriteByte(13); stream.WriteByte(10);
                        stream.Flush();
                        Thread.Sleep(25);
                    }
                    byte[] last = Encoding.ASCII.GetBytes("0\r\n\r\n");
                    stream.Write(last, 0, last.Length);
                    stream.Flush();
                }
                else
                {
                    byte[] body = Encoding.UTF8.GetBytes("hello " + path + " via " + role + " plain");
                    head += "Content-Length: " + body.Length + "\r\nConnection: close\r\n\r\n";
                    byte[] header = Encoding.ASCII.GetBytes(head);
                    stream.Write(header, 0, header.Length);
                    stream.Write(body, 0, body.Length);
                    stream.Flush();
                }
            }
            catch { }
            finally { try { client.Close(); } catch { } }
        }

        static string ReadHeaders(Stream stream)
        {
            var text = new StringBuilder();
            var one = new byte[1];
            while (text.Length < 65536)
            {
                int got;
                try { got = stream.Read(one, 0, 1); }
                catch { break; }
                if (got <= 0) break;
                text.Append((char)one[0]);
                if (text.Length >= 4 && text.ToString(text.Length - 4, 4) == "\r\n\r\n") break;
            }
            return text.ToString();
        }

        static string FirstToken(string request)
        {
            int end = request.IndexOf("\r\n");
            if (end < 0) end = request.Length;
            var parts = request.Substring(0, end).Split(' ');
            return parts.Length > 1 ? parts[1] : "/";
        }

        public void Dispose() { stopping = true; try { listener.Stop(); } catch { } }
    }

    public sealed class Socks : IDisposable
    {
        readonly TcpListener listener;
        volatile bool stopping;
        public int Port { get; private set; }
        public string Role;
        public string User;
        public string Password;
        public byte ReplyCode;             // what a CONNECT gets back
        public byte MethodReply = 0x00;    // 0xFF = no acceptable methods
        public string LastRequest = "";
        public string ReportPath = "";    // written after every CONNECT so a test can assert ATYP
        public bool CloseAfterGreeting;   // accept, answer the greeting, then hang up
        public int Requests;
        public string ForwardTo = "127.0.0.1";
        public int ForwardPort;
        public bool Silent;                // accept and never answer

        public Socks(string role, int port)
        {
            Role = role;
            listener = new TcpListener(IPAddress.Parse("127.0.0.1"), port);
            listener.Start();
            Port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var thread = new Thread(Loop) { IsBackground = true, Name = role };
            thread.Start();
        }

        void Loop()
        {
            while (!stopping)
            {
                TcpClient client;
                try { client = listener.AcceptTcpClient(); }
                catch { return; }
                Interlocked.Increment(ref Requests);
                ThreadPool.QueueUserWorkItem(_ => Handle(client));
            }
        }

        static bool Exact(TcpClient client, byte[] wanted)
        {
            client.ReceiveTimeout = 8000;
            var got = new byte[wanted.Length];
            int read = 0;
            while (read < wanted.Length)
            {
                int n = client.GetStream().Read(got, read, wanted.Length - read);
                if (n <= 0) return false;
                read += n;
            }
            for (int i = 0; i < wanted.Length; i++) if (got[i] != wanted[i]) return false;
            return true;
        }

        void Report(string line)
        {
            if (ReportPath == "") return;
            try { File.WriteAllText(ReportPath, line); } catch { }
        }

        void Handle(TcpClient client)
        {
            TcpClient upstream = null;
            try
            {
                client.ReceiveTimeout = 8000;
                client.SendTimeout = 8000;
                var stream = client.GetStream();
                if (Silent) return;   // accept and go quiet: the client must time out

                byte[] greeting = new byte[2];
                if (!Exact(client, greeting)) return;
                int methodCount = stream.ReadByte();
                if (methodCount < 0) return;
                var methods = new byte[methodCount];
                int read = 0;
                while (read < methodCount)
                {
                    int n = stream.Read(methods, read, methodCount - read);
                    if (n <= 0) return;
                    read += n;
                }
                bool hasNoAuth = Array.IndexOf(methods, (byte)0x00) >= 0;
                bool hasUserPass = Array.IndexOf(methods, (byte)0x02) >= 0;
                byte chosen;
                if (MethodReply == 0xFF) chosen = 0xFF;
                else if (hasUserPass && Password != null) chosen = 0x02;
                else if (hasNoAuth) chosen = 0x00;
                else chosen = MethodReply;
                stream.WriteByte(chosen);
                stream.Flush();
                if (chosen == 0xFF) return;
                if (CloseAfterGreeting) return;   // a proxy that drops the connection
                if (chosen == 0x02)
                {
                    var version = new byte[1];      // RFC 1929
                    if (!Exact(client, version)) return;
                    int userLength = stream.ReadByte();
                    if (userLength < 0) return;
                    var user = new byte[userLength];
                    read = 0;
                    while (read < userLength)
                    {
                        int n = stream.Read(user, read, userLength - read);
                        if (n <= 0) return;
                        read += n;
                    }
                    int passLength = stream.ReadByte();
                    if (passLength < 0) return;
                    var pass = new byte[passLength];
                    read = 0;
                    while (read < passLength)
                    {
                        int n = stream.Read(pass, read, passLength - read);
                        if (n <= 0) return;
                        read += n;
                    }
                    string gotUser = Encoding.UTF8.GetString(user);
                    string gotPass = Encoding.UTF8.GetString(pass);
                    bool ok = gotUser == (User ?? "") && gotPass == (Password ?? "") && ReplyCode == 0;
                    stream.WriteByte(ok ? (byte)0x00 : (byte)0x01);
                    stream.Flush();
                    Report((ok ? "auth-ok " : "auth-failed ") + gotUser + " plen=" + gotPass.Length);
                    if (!ok) return;
                }

                byte[] request = new byte[4];       // CONNECT
                if (!Exact(client, request)) return;
                if (request[1] != 0x01) { WriteReply(stream, 0x07); return; }
                byte atyp = request[3];
                string address = "";
                if (atyp == 0x01)
                {
                    var raw = new byte[4];
                    if (!Exact(client, raw)) return;
                    address = new IPAddress(raw).ToString();
                }
                else if (atyp == 0x03)
                {
                    int length = stream.ReadByte();
                    if (length < 0) return;
                    var raw = new byte[length];
                    read = 0;
                    while (read < length)
                    {
                        int n = stream.Read(raw, read, length - read);
                        if (n <= 0) return;
                        read += n;
                    }
                    address = Encoding.ASCII.GetString(raw);
                }
                else if (atyp == 0x04)
                {
                    var raw = new byte[16];
                    if (!Exact(client, raw)) return;
                    address = new IPAddress(raw).ToString();
                }
                else { WriteReply(stream, 0x08); return; }
                var portBytes = new byte[2];
                if (!Exact(client, portBytes)) return;
                int targetPort = (portBytes[0] << 8) | portBytes[1];
                LastRequest = atyp + " " + address + " " + targetPort;
                Report("connect " + LastRequest);

                if (ReplyCode != 0) { WriteReply(stream, ReplyCode); return; }
                if (ForwardPort == 0) { WriteReply(stream, 0x05); return; }

                upstream = new TcpClient();
                upstream.Connect(ForwardTo, ForwardPort);
                var up = upstream.GetStream();
                WriteReply(stream, 0x00, atyp, address, targetPort);
                var relay = new Thread(() => Pump(stream, up)) { IsBackground = true };
                relay.Start();
                Pump(up, stream);
            }
            catch { }
            finally
            {
                try { if (upstream != null) upstream.Close(); } catch { }
                try { client.Close(); } catch { }
            }
        }

        static void Pump(Stream from, Stream to)
        {
            var buffer = new byte[16384];
            try
            {
                while (true)
                {
                    int n = from.Read(buffer, 0, buffer.Length);
                    if (n <= 0) break;
                    to.Write(buffer, 0, n);
                    to.Flush();
                }
            }
            catch { }
        }

        static void WriteReply(NetworkStream stream, byte code, byte atyp = 0x01, string address = "0.0.0.0", int port = 0)
        {
            var reply = new List<byte>();
            reply.Add(0x05); reply.Add(code); reply.Add(0x00); reply.Add(atyp);
            if (atyp == 0x01) reply.AddRange(IPAddress.Parse(address).GetAddressBytes());
            else if (atyp == 0x03)
            {
                var text = Encoding.ASCII.GetBytes(address);
                reply.Add((byte)text.Length);
                reply.AddRange(text);
            }
            var raw = reply.ToArray();
            stream.Write(raw, 0, raw.Length);
            stream.WriteByte((byte)((port >> 8) & 0xFF));
            stream.WriteByte((byte)(port & 0xFF));
            stream.Flush();
        }

        public void Dispose() { stopping = true; try { listener.Stop(); } catch { } }
    }
}
'@

Add-Type -TypeDefinition $code -Language CSharp

function Add-Recorder {
    param([string]$Role)
    $recorder = New-Object Tb287+Recorder($Role, 0)
    [void]$owned.Add($recorder)
    return $recorder
}

function Add-Socks {
    param([string]$Role, [int]$ForwardPort, [byte]$ReplyCode = 0, [bool]$NoMethods = $false,
        [bool]$CloseAfterGreeting = $false, [bool]$Silent = $false, [string]$User = '', [string]$Password = '')
    $socks = New-Object Tb287+Socks($Role, 0)
    $socks.ForwardPort = $ForwardPort
    $socks.ReplyCode = $ReplyCode
    if ($NoMethods) { $socks.MethodReply = [byte]0xFF }
    $socks.CloseAfterGreeting = $CloseAfterGreeting
    $socks.Silent = $Silent
    $socks.User = $User
    $socks.Password = $Password
    $socks.ReportPath = Join-Path $workFull ($Role + '.txt')
    [void]$owned.Add($socks)
    return $socks
}

try {
    $plain = Add-Recorder -Role 'plain'

    $securePort = Start-TlsServer -Role 'secure' -Port (Get-FreePort) -Certificate $leafLocalhost
    $wrongnamePort = Start-TlsServer -Role 'wrongname' -Port (Get-FreePort) -Certificate $leafWrong
    $expiredPort = Start-TlsServer -Role 'expired' -Port (Get-FreePort) -Certificate $leafExpired
    $roguePort = Start-TlsServer -Role 'rogue' -Port (Get-FreePort) -Certificate $leafRogue

    # The fixed 443/8443 pair is what proves "ssl decides, not the port" at those
    # two ports. Both are optional: a busy port is reported as SKIP, never as a
    # pass, and the same checks also run through the proxy on those target ports.
    $port443 = 0
    $port8443 = 0
    if (Test-PortFree -Port 443) {
        $port443 = Start-TlsServer -Role 'fixed443' -Port 443 -Certificate $leafLocalhost
    } else {
        Write-Output 'SKIP fixed 443 (port busy)'
    }
    if (Test-PortFree -Port 8443) {
        $port8443 = Start-TlsServer -Role 'fixed8443' -Port 8443 -Certificate $leafLocalhost
    } else {
        Write-Output 'SKIP fixed 8443 (port busy)'
    }

    $socksOpen = Add-Socks -Role 'socks-open' -ForwardPort $plain.Port
    $socksAuth = Add-Socks -Role 'socks-auth' -ForwardPort $plain.Port -User 'user' -Password 'pass'
    $socksSilent = Add-Socks -Role 'socks-silent' -Silent $true
    $socksSecure = Add-Socks -Role 'socks-secure' -ForwardPort $securePort
    $socksNoMethod = Add-Socks -Role 'socks-nomethod' -ForwardPort $plain.Port -NoMethods $true
    $socksClose = Add-Socks -Role 'socks-close' -ForwardPort $plain.Port -CloseAfterGreeting $true

    $socksReplies = [ordered]@{}
    foreach ($code in 1, 2, 3, 4, 5, 6, 7, 8, 9) {
        $name = 'socks-rep' + $code
        $socksReplies["rep$code"] = (Add-Socks -Role $name -ForwardPort $plain.Port -ReplyCode ([byte]$code)).Port
    }

    $report = [ordered]@{
        plain_port = $plain.Port
        secure_port = $securePort
        wrongname_port = $wrongnamePort
        expired_port = $expiredPort
        rogue_port = $roguePort
        port443 = $port443
        port8443 = $port8443
        socks_open_port = $socksOpen.Port
        socks_auth_port = $socksAuth.Port
        socks_silent_port = $socksSilent.Port
        socks_secure_port = $socksSecure.Port
        socks_nomethod_port = $socksNoMethod.Port
        socks_close_port = $socksClose.Port
        socks_replies = $socksReplies
        socks_report_dir = $workFull
        ca_pem = $ca.Cert
        prefix = $prefix
    }

    # The openssl children, so a killed fixture does not leave servers listening.
    Set-Content -Path (Join-Path $workFull 'children.json') -Encoding UTF8 -Value (
        $children | ForEach-Object {
            [pscustomobject]@{ Role = $_.Role; Id = $_.Process.Id }
        } | ConvertTo-Json -Compress)

    Set-Content -Path $Info -Value ($report | ConvertTo-Json -Compress) -Encoding UTF8
    Write-Output ('READY ' + ($report | ConvertTo-Json -Compress))

    $stopFile = Join-Path $workFull 'stop'
    while (-not (Test-Path $stopFile)) { Start-Sleep -Milliseconds 200 }
} finally {
    foreach ($item in $owned) {
        try { $item.Dispose() } catch { }
    }
    foreach ($child in $children) {
        try { if (-not $child.Process.HasExited) { $child.Process.Kill() } } catch { }
    }
    # Nothing else to clean: no key container was ever created (see the header).
}