using System.Data;
using System.Net.WebSockets;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json.Linq;

namespace KahootGod;

internal static class Program
{
    private const int JoinCode = 9032754;
    private static readonly HttpClient Client = new();

    private static long _offset;

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
        
        
        
        var webSocketTask = Task.Run(async () => await WebSocketThing(new Uri($"wss://kahoot.it/cometd/{JoinCode}/{token}")));
        
        webSocketTask.Wait();
        
        var e = webSocketTask.Result;
            
        Console.WriteLine(e + "E");
            
            
    }

    private static async Task<string> WebSocketThing(Uri uri)
    {
        using ClientWebSocket clientWebSocket = new();
        await clientWebSocket.ConnectAsync(uri, default);

        var packetString =
            """[{"id":"1","version":"1.0","minimumVersion":"1.0","channel":"/meta/handshake","supportedConnectionTypes":["websocket","long-polling","callback-polling"],"advice":{"timeout":60000,"interval":0},"ext":{"ack":true,"timesync":{"tc":1694650747824,"l":0,"o":0}}}]""";

        Console.WriteLine(packetString);
            
        var bytes = Encoding.UTF8.GetBytes(packetString);
        var result = await clientWebSocket.ReceiveAsync(bytes, default);
            
        var res = Encoding.UTF8.GetString(bytes);
            
        Console.WriteLine(result.ToString());

        //await clientWebSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Client closed", default);

        return res + "E";
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
    
    /*{
        "twoFactorAuth": false,
        "namerator": false,
        "participantId": false,
        "smartPractice": false,
        "collaborations": false,
        "gameType": "normal",
        "liveGameId": "41f2d8e063cbb71d31de44ba35a1e7e13a29803eac09b792",
        "challenge": "decode.call(this, 'TXQmCymCwO542x5LxzuYrk8zw4ngWad4XQQeSML0eWoH7wbY5fgN303ChbID304oI4ul2LpuXgtDIVeLGLW4rNYKT4aUWv3TODEw'); function decode(message) {var offset = 68 + \t 56 + \t 70 + \t 65 + \t 64 + \t 27 \t *\t 43; if(\t this\t .angular\t .\t isString   (\t offset\t )) \t console   . log\t (\"Offset derived as: {\", offset, \"}\"); return  \t _ \t .   replace \t ( message,/./g, function(char, position) {return String.fromCharCode((((char.charCodeAt(0)*position)+ offset ) % 77) + 48);});}"
    }


    CHALLENGE

    decode.call(this, 'TXQmCymCwO542x5LxzuYrk8zw4ngWad4XQQeSML0eWoH7wbY5fgN303ChbID304oI4ul2LpuXgtDIVeLGLW4rNYKT4aUWv3TODEw');

    function decode(message) {
        var offset = 68+56+70+65+64?27*43;
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

        Console.WriteLine($"Message: {message}");
        Console.WriteLine($"Decoded: {decoded}");
        
        //Console.WriteLine($"message: {message[0]}, unicode: {messageUnicode[0]}, decoded unicode: {messageDecoded[0]}, decoded message: {decoded[0]}");
            
        return decoded;
    }
    
    private static string GetToken(string encodedToken, string decodedToken) {
        
        var encodedTokenBytes = new byte[]
        {
            0x1F, 0x22, 0x4B, 0x62, 0x00, 0x5A, 0x1A, 0x06, 0x76, 0x51, 0x4A, 0x52, 0x6E, 0x74, 0x78, 0x74, 0x34, 0x6E, 0x3E, 0x1D, 0x5E, 0x7E, 0x42, 0x5C, 0x06, 0x04, 0x53, 0x45, 0x56, 0x7E, 0x43, 0x55, 0x70, 0x0F, 0x56, 0x49, 0x50, 0x0B, 0x1A, 0x01, 0x6A, 0x56, 0x0A, 0x64, 0x03, 0x75, 0x78, 0x53, 0x77, 0x4B, 0x7B, 0x05, 0x43, 0x77, 0x5B, 0x27, 0x06, 0x75, 0x02, 0x0D, 0x0F, 0x70, 0x13, 0x66, 0x4D, 0x01, 0x6C, 0x7D, 0x58, 0x5D, 0x51, 0x5F, 0x59, 0x0E, 0x0F, 0x13, 0x63, 0x4A, 0x56, 0x02, 0x5D, 0x30, 0x09, 0x7E, 0x51, 0x06, 0x6B, 0x7A, 0x24, 0x02, 0x18, 0x05, 0x02, 0x53, 0x7F, 0x04
        };

        encodedToken = Encoding.UTF8.GetString(encodedTokenBytes);

        decodedToken =
            "|D{Qfc|`O4rfYEKBQ][{:Kq>?aasgMz0C:7|g=y9Xf=W:BL`C|OdqC9E`E4>;@wR|7[Km>`;m?=pV|47nTlGgdSHEd|6feH=?k=P";
        
        Console.WriteLine("===================================");
        Console.WriteLine(encodedToken);
        Console.WriteLine(decodedToken);
        Console.WriteLine("===================================");


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