using System.Data;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.WebSockets;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json.Linq;

namespace KahootGod;

internal static partial class Program
{
    /// <summary>
    /// The Join Code for the Kahoot Game
    /// </summary>
    private const int JoinCode = 8937553;
    /// <summary>
    /// The nickname for the fake account
    /// </summary>
    private const string Nickname = "KahootGod";
    
    
    private static readonly HttpClient Client = new();
    private static readonly ClientWebSocket Socket = new();
    
    private static string _clientId = "";

    private static long _offset;

    private static int _lastPackedId;
    private static int _ack;

    private static long _latency;
    
    private static JObject _receivedPacket = new();
    private static bool _newPacket;
    
    
    private static bool _endCommunication;
    private static bool _ready;

    private static readonly string Null = Encoding.UTF8.GetString(new byte[] { 0x00 });

    /// <summary>
    /// Entrypoint, initializes everything and connects to Kahoot.
    /// </summary>
    private static void Main()
    {
        Console.Clear();
        
        var result = Client.Send(new HttpRequestMessage(new HttpMethod("GET"), $"https://kahoot.it/reserve/session/{JoinCode}/?{DateTimeOffset.Now.ToUnixTimeMilliseconds()}"));

        if (result.StatusCode == HttpStatusCode.NotFound)
        {
            Console.WriteLine("No Game Hosted with Join Code " + JoinCode);
            return;
        }
        
        var replyStream = result.Content.ReadAsStream();
        var replyBytes = new Span<byte>(new byte[replyStream.Length]);

        replyStream.Read(replyBytes);
            
            
        var reply = Encoding.ASCII.GetString(replyBytes);
        var challengeSolution = SolveChallenge(DeserializeChallenge(JObject.Parse(reply)));
        
        var sessionToken = result.Headers.GetValues("x-kahoot-session-token").ToArray()[0];
        var base64EncodedBytes = Convert.FromBase64String(sessionToken);
        sessionToken = Encoding.UTF8.GetString(base64EncodedBytes);

        var token = GetToken(sessionToken, challengeSolution);

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"Websocket Token: {token}");
        
        
        var webSocketTask = Task.Run(async () => await WebSocketHandler(new Uri($"wss://kahoot.it/cometd/{JoinCode}/{token}")));
        
        webSocketTask.Wait();
    }

    /// <summary>
    /// Interfaces with Kahoot, creates a fake account, and plays the game.
    /// </summary>
    /// <param name="uri">The URL to connect to the websocket</param>
    private static async Task WebSocketHandler(Uri uri)
    {
        await Socket.ConnectAsync(uri, default);

        var keepAlive = WebsocketBackground();

        while (!_ready)
        {
            Thread.Sleep(100);
        }
        
        // all of the packet messaging goes here
        
        
        #region Login 1
        var packetString = GetEmbeddedResource("KahootGod.PacketScaffolds.Login1.json");
        var packetJson = JObject.Parse(packetString);

        // set packet information
        packetJson["id"] = _lastPackedId;
        packetJson["data"]!["gameid"] = JoinCode;
        packetJson["data"]!["name"] = Nickname;
        packetJson["clientId"] = _clientId;

        SendPacket(packetJson);

        
        #endregion
        
        Thread.Sleep(10000);
        
        
        #region Login 2
        packetString = GetEmbeddedResource("KahootGod.PacketScaffolds.Login2.json");
        packetJson = JObject.Parse(packetString);

        // set packet information
        packetJson["id"] = _lastPackedId;
        packetJson["data"]!["gameid"] = JoinCode;
        packetJson["clientId"] = _clientId;

        SendPacket(packetJson);


        
        #endregion
        
        //SendKeepAlivePacket();

        
        await keepAlive;

        
        // close the websocket
        _endCommunication = true;
        await Socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Client closed", default);
        Socket.Dispose();

        await keepAlive;
    }

    /// <summary>
    /// Manages a background thread that receives packets and sends Keep-Alive packets at the correct time.
    /// </summary>
    /// <exception cref="Exception">Thrown if an invalid packet gets received</exception>
    private static async Task WebsocketBackground()
    {
        while (!_endCommunication)
        {
            SendKeepAlivePacket();
            
            if (_lastPackedId == 3)
                _ready = true;
            
            var isKeepAliveReply = false;
            var result = new JObject();
            while (!isKeepAliveReply)
            {
                var bytes = new byte[1024];
                await Socket.ReceiveAsync(bytes, default);
                var resultString = Encoding.UTF8.GetString(bytes).Replace(Null, "")[1..^1];
                result = JObject.Parse(resultString);
                
                
                // normal keep-alive packet
                if (result["channel"]!.Value<string>() == "/meta/connect")
                {
                    _ack = result["ext"]!["ack"]!.Value<int>();
                    isKeepAliveReply = true;
                }
                
                // first keep-alive packet
                if (result["channel"]!.Value<string>() == "/meta/handshake" && _lastPackedId == 1)
                {
                    isKeepAliveReply = true;
                }

                if (isKeepAliveReply) break;
                
                
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"<-IN--[{result["channel"]!.Value<string>()}]-");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine(CleanString(resultString));

                
                // set the received packet
                _receivedPacket = result;
                _newPacket = true;
            }
            
            //
            if (_lastPackedId == 1)
            {
                _clientId = result["clientId"]!.Value<string>() ?? "";
                
                _latency = -result["ext"]!["timesync"]!["a"]!.Value<long>();

                if (_clientId == null)
                    throw new Exception("ClientId was null");
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"ClientId: {_clientId}");
                Console.WriteLine($"Latency: {_latency}");

            }

        }

        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("Shutting Down Websocket Background Thread");


        _endCommunication = false;
    }

    /// <summary>
    /// Creates and sends a Keep-Alive packet, dynamically generating it based off of the time and _lastPacketId.
    /// </summary>
    private static void SendKeepAlivePacket()
    {
        JObject packetJson;
            
        switch (_lastPackedId)
        {
            case 0:
            {
                packetJson = JObject.Parse(GetEmbeddedResource("KahootGod.PacketScaffolds.KeepAlive1.json"));
                    
                break;
            }
            case 1:
            {
                packetJson = JObject.Parse(GetEmbeddedResource("KahootGod.PacketScaffolds.KeepAlive2.json"));

                // set sending client id
                packetJson["clientId"] = _clientId;
                    
                break;
            }
            default:
            {
                packetJson = JObject.Parse(GetEmbeddedResource("KahootGod.PacketScaffolds.KeepAlive.json"));

                // set packet id, client id and ack
                packetJson["id"] = _lastPackedId+1;
                packetJson["clientId"] = _clientId;
                packetJson["ext"]!["ack"] = _ack;

                break;
            }
        }

        packetJson["ext"]!["timesync"]!["tc"] = DateTimeOffset.Now.ToUnixTimeMilliseconds();
        packetJson["ext"]!["timesync"]!["l"] = _latency;
        packetJson["ext"]!["timesync"]!["o"] = 0; // until I find out how to calculate the time offset between client and server

        
        SendPacket(packetJson, true);
    }
    
    /// <summary>
    /// Deserializes a challenge from JSON and extracts the offset (stored in _offset) and challenge string (returned).
    /// </summary>
    /// <param name="challenge">The challenge JSON</param>
    /// <returns>The challenge string</returns>
    private static string DeserializeChallenge(JObject challenge)
    {
        var challengeString = CleanString(challenge["challenge"].ToString());
            
        var message = MessageRegex().Match(challengeString).ToString()[1..^1];
        var offsetEquation = OffsetEquationRegex().Match(challengeString).ToString();
            
        _offset = Convert.ToInt64(new DataTable().Compute(offsetEquation, null));

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"Challenge: {offsetEquation} = {_offset}");

        return message;
    }
    
    /// <summary>
    /// Solves the challenge based on the supplied challenge string. Requires _offset to be set to the offset calculated in DeserializeChallenge.
    /// </summary>
    /// <param name="message">The challenge string</param>
    /// <returns></returns>
    private static string SolveChallenge(string message)
    {
        var messageUnicode = new Span<byte>(new byte[message.Length]);
        var messageDecoded = new Span<byte>(new byte[message.Length]);

        Encoding.UTF8.GetBytes(message, messageUnicode);
            
        for (var i = 0; i < message.Length; i++)
        {
            messageDecoded[i] = (byte)((messageUnicode[i] * i + _offset) % 77 + 48);
        }
            
        var decoded = Encoding.UTF8.GetString(messageDecoded);
        
        return decoded;
    }
    
    /// <summary>
    /// Combines the session token and challenge solution into the websocket token.
    /// </summary>
    /// <param name="sessionToken">The session token</param>
    /// <param name="challengeSolution">The solution to the challenge</param>
    /// <returns>A websocket key (96-char hexadecimal if all goes to plan)</returns>
    private static string GetToken(string sessionToken, string challengeSolution) {
        
        var encodedTokenUnicode = new Span<byte>(new byte[sessionToken.Length]);
        var decodedTokenUnicode = new Span<byte>(new byte[challengeSolution.Length]);

        var tokenUnicode = new Span<byte>(new byte[sessionToken.Length]);

        Encoding.UTF8.GetBytes(sessionToken, encodedTokenUnicode);
        Encoding.UTF8.GetBytes(challengeSolution, decodedTokenUnicode);

        for (var i = 0; i < sessionToken.Length; i++) {
            var e = encodedTokenUnicode[i];
            var d = decodedTokenUnicode[i % challengeSolution.Length];

            tokenUnicode[i] = (byte)(e ^ d);
        }
        
        return Encoding.UTF8.GetString(tokenUnicode);
    }

    /// <summary>
    /// Fetches an embedded resource.
    /// </summary>
    /// <param name="resourceName">The path to the resource</param>
    /// <returns>The contents of the resource, parsed as a string</returns>
    /// <exception cref="IOException">Thrown when the requested resource could not be found</exception>
    private static string GetEmbeddedResource(string resourceName)
    {
        var assembly = Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream(resourceName);

        if (stream == null)
            throw new IOException("Requested embedded file '" + resourceName + "' could not be found.");
        
        return new StreamReader(stream).ReadToEnd();
    }

    /// <summary>
    /// Waits for a packet to arrive, then returns it.
    /// </summary>
    /// <returns>The packet that arrived</returns>
    private static JObject WaitForPacket()
    {
        while (!_newPacket)
        {
            Thread.Sleep(100);
        }

        _newPacket = false;

        return _receivedPacket;
    }

    /// <summary>
    /// Sends a packet with the specified JSON contents.
    /// </summary>
    /// <param name="content">A JObject containing the content to send</param>
    /// <param name="keepAlive">(optional) Treat the packet as a Keep-Alive packet (logging purposes)</param>
    /// <exception cref="WebSocketException">Thrown if the websocket (Socket) has not been initialized</exception>
    private static async void SendPacket(JObject content, bool keepAlive = false)
    {
        _lastPackedId++;

        if (Socket == null)
            throw new WebSocketException("Websocket not initialized");
        
        var packetString = content.ToString();
        var segment = new ArraySegment<byte>(Encoding.UTF8.GetBytes(packetString));
        await Socket.SendAsync(segment, WebSocketMessageType.Text, true, CancellationToken.None);

        if (keepAlive)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"Keep-Alive Packet Sent (#{_lastPackedId})");
        }
        else
        {
            
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"--OUT-[{_lastPackedId}]->");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(CleanString(packetString));

        }
        
    }
    
    /// <summary>
    /// Removes all characters from a string that are not:<br></br>
    /// 0-9a-zA-Z"'(){}\/.,:;+-*%=
    /// </summary>
    /// <param name="value">The original string</param>
    /// <returns>The cleaned string</returns>
    private static string CleanString(string value)
    {
        const string allowedChars = "01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\"'(){}\\/.,:;+-*%=";
        return new string(value.Where(c => allowedChars.Contains(c)).ToArray());
    }

    [GeneratedRegex("'[0-9a-zA-Z]{100}'")]
    private static partial Regex MessageRegex();
    
    [GeneratedRegex(@"([0-9()]+\s*[+-/\*]\s*)+[0-9()]*")]
    private static partial Regex OffsetEquationRegex();
}