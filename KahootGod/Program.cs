using System.Data;
using System.Net.WebSockets;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json.Linq;

namespace KahootGod;

internal static class Program
{
    private const int JoinCode = 8027748;
    private static readonly HttpClient Client = new();

    private static long _offset;

    private static bool _endCommunication = false;

    private static string _null = Encoding.UTF8.GetString(new byte[] { 0x00 });

    private static void Main()
    {
        var result = Client.Send(new HttpRequestMessage(new HttpMethod("GET"), $"https://kahoot.it/reserve/session/{JoinCode}/?{DateTimeOffset.Now.ToUnixTimeMilliseconds()}"));

        var replyStream = result.Content.ReadAsStream();
        var replyBytes = new Span<byte>(new byte[replyStream.Length]);

        replyStream.Read(replyBytes);
            
            
        var reply = Encoding.ASCII.GetString(replyBytes);

        
        var solved = DecodeChallenge(DeserializeChallenge(JObject.Parse(reply)));

        var sessionToken = result.Headers.GetValues("x-kahoot-session-token").ToArray()[0];
        
        var base64EncodedBytes = Convert.FromBase64String(sessionToken);
        sessionToken = Encoding.UTF8.GetString(base64EncodedBytes);

        var token = GetToken(sessionToken, solved);
        
        
        
        var webSocketTask = Task.Run(async () => await WebSocketHandler(new Uri($"wss://kahoot.it/cometd/{JoinCode}/{token}")));
        
        webSocketTask.Wait();
        
            
    }

    private static async Task WebSocketHandler(Uri uri)
    {
        using ClientWebSocket socket = new();
        await socket.ConnectAsync(uri, default);

        #region var packetString = (Start Message)
        var packetString =
            """
            [
                {
                    "id":"1",
                    "version":"1.0",
                    "minimumVersion":"1.0",
                    "channel":"/meta/handshake",
                    "supportedConnectionTypes":["websocket","long-polling","callback-polling"],
                    "advice":{"timeout":60000,"interval":0},
                    "ext":{
                        "ack":true,
                        "timesync":{
                            "tc":
            """ + DateTimeOffset.Now.ToUnixTimeMilliseconds() + "," + 
            """
            
                            "l":0,"o":0
                        }
                    }
                }
            ]
            """;
        #endregion
        
        var bytes = Encoding.UTF8.GetBytes(packetString);
        var segment = new ArraySegment<byte>(bytes);
        bytes = new byte[1024];
        
        await socket.SendAsync(segment, WebSocketMessageType.Text, true, CancellationToken.None);
        await socket.ReceiveAsync(bytes, default);
        
        var resultString = Encoding.UTF8.GetString(bytes).Replace(_null, "")[1..^1];
        
        var result = JObject.Parse(resultString);
            

        var clientId = result["clientId"].Value<string>();
        
        Console.WriteLine(clientId);

        var keepAlive = WebsocketKeepAlive(socket, clientId);

        _endCommunication = true;
        await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Client closed", default);


        await keepAlive;
    }

    private static async Task WebsocketKeepAlive(WebSocket socket, string clientId)
    {
        var count = 0;
        
        while (!_endCommunication)
        {
            var packetString =
                """
                [
                    {
                        "id":
                """ + count + "," + 
                """
                      
                              "channel":"/meta/connect",
                              "connectionType":"websocket",
                              "clientId":
                """ + clientId + "," +
                """
                      
                              "ext":{
                                  "ack":8,
                                  "timesync":{
                                      "tc":
                """ + DateTimeOffset.Now.ToUnixTimeMilliseconds() + "," +
                """
                      
                                      "l":35,
                                      "o":-150
                                  }
                              }
                          }
                      ]
                """;
            
            Console.WriteLine(packetString);
            
            var bytes = Encoding.UTF8.GetBytes(packetString);
            var segment = new ArraySegment<byte>(bytes);
            await socket.SendAsync(segment, WebSocketMessageType.Text, true, CancellationToken.None);
            
            await socket.ReceiveAsync(bytes, default);

            // wait 30s, then send another packet
            Thread.Sleep(20000);
            count++;
        }

        _endCommunication = false;
    }
        
    private static string DeserializeChallenge(JObject reply)
    {
        var challenge = FormatString(reply["challenge"].ToString());
            
        var message = Regex.Match(challenge, @"'[0-9a-zA-Z]{100}'").ToString()[1..^1];
        var offsetEquation = Regex.Match(challenge, @"([0-9()]+\s*[+-/\*]\s*)+[0-9()]*").ToString();
            
        _offset = Convert.ToInt64(new DataTable().Compute(offsetEquation, null));
            
        Console.WriteLine($"Challenge: {offsetEquation} = {_offset}");

        return message;
    }
    
    /*
     reply json
     {
        "twoFactorAuth": false,
        "namerator": false,
        "participantId": false,
        "smartPractice": false,
        "collaborations": false,
        "gameType": "normal",
        "liveGameId": "41f2d8e063cbb71d31de44ba35a1e7e13a29803eac09b792",
        "challenge": "decode.call(this, 'TXQmCymCwO542x5LxzuYrk8zw4ngWad4XQQeSML0eWoH7wbY5fgN303ChbID304oI4ul2LpuXgtDIVeLGLW4rNYKT4aUWv3TODEw'); function decode(message) {var offset = 68 + \t 56 + \t 70 + \t 65 + \t 64 + \t 27 \t *\t 43; if(\t this\t .angular\t .\t isString   (\t offset\t )) \t console   . log\t (\"Offset derived as: {\", offset, \"}\"); return  \t _ \t .   replace \t ( message,/./g, function(char, position) {return String.fromCharCode((((char.charCodeAt(0)*position)+ offset ) % 77) + 48);});}"
    }


    CHALLENGE (made readable)

    decode.call(this, '(100 char b64(probably) string)');

    function decode(message) {
        var offset = (randomized math operation);
        if(this.angular.isString(offset))
            console.log(\"Offset derived as: {\", offset, \"}\");
        return _.replace(message,/./g, function(char, position) {
                return String.fromCharCode((((char.charCodeAt(0)*position)+ offset ) % 77) + 48);
            }
        );
    }
    */
    
    private static string DecodeChallenge(string message)
    {
        var messageUnicode = new Span<byte>(new byte[message.Length]);
        var messageDecoded = new Span<byte>(new byte[message.Length]);

        Encoding.UTF8.GetBytes(message, messageUnicode);
            
        for (var i = 0; i < message.Length; i++)
        {
            messageDecoded[i] = (byte)((((messageUnicode[i] * i) + _offset) % 77) + 48);
        }
            
        var decoded = Encoding.UTF8.GetString(messageDecoded);

        //Console.WriteLine($"message: {message[0]}, unicode: {messageUnicode[0]}, decoded unicode: {messageDecoded[0]}, decoded message: {decoded[0]}");
            
        return decoded;
    }
    
    private static string GetToken(string encodedToken, string decodedToken) {
        

        var encodedTokenUnicode = new Span<byte>(new byte[encodedToken.Length]);
        var decodedTokenUnicode = new Span<byte>(new byte[decodedToken.Length]);

        var tokenUnicode = new Span<byte>(new byte[encodedToken.Length]);

        Encoding.UTF8.GetBytes(encodedToken, encodedTokenUnicode);
        Encoding.UTF8.GetBytes(decodedToken, decodedTokenUnicode);

        for (var i = 0; i < encodedToken.Length; i++) {
            var e = encodedTokenUnicode[i];
            var d = decodedTokenUnicode[i % decodedToken.Length];

            tokenUnicode[i] = (byte)(e ^ d);
            
            // eslint-disable-next-line
            // n += String.fromCharCode(e ^ d);
            
        }

        var result = Encoding.UTF8.GetString(tokenUnicode);
        
        Console.WriteLine(result);

        return result;
    }


    
    private static string FormatString(string value)
    {
        var allowedChars = "01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\"'(){}\\.;+-*/%:= ";
        return new string(value.Where(c => allowedChars.Contains(c)).ToArray());
    }

    private static string CharGen(char character, long count)
    {
        var result = "";

        for (long i = 0; i < count; i++)
        {
            result += character;
        }

        return result;
    }
}