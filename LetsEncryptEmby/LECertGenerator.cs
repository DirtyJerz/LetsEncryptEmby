
using System;
using System.IO;
using System.Net;
using System.Text;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Oocx.Asn1PKCS.PKCS10;
using Oocx.Asn1PKCS.Asn1BaseTypes;


namespace LetsEncryptEmby
{
    public class JsonWebKey
    {
        [JsonProperty("kty")]
        public string KeyType { get; set; }

        [JsonProperty("kid")]
        public string KeyId { get; set; }

        [JsonProperty("use")]
        public string Use { get; set; }

        [JsonProperty("n")]
        public string Modulus { get; set; }

        [JsonProperty("e")]
        public string Exponent { get; set; }

        [JsonProperty("d")]
        public string D { get; set; }

        [JsonProperty("p")]
        public string P { get; set; }

        [JsonProperty("q")]
        public string Q { get; set; }

        [JsonProperty("dp")]
        public string DP { get; set; }

        [JsonProperty("dq")]
        public string DQ { get; set; }

        [JsonProperty("qi")]
        public string InverseQ { get; set; }

        [JsonProperty("alg")]
        public string Algorithm { get; set; }

    }

    public class JWSHeader
    {

        [JsonProperty("alg")]
        public string Algorithm { get; set; }

        [JsonProperty("jwk")]
        public JsonWebKey Key { get; set; }

    }

    public class JWSMessage
    {
        [JsonProperty("header")]
        public JWSHeader Header { get; set; }

        [JsonProperty("protected")]
        public string Protected { get; set; }

        [JsonProperty("payload")]
        public string Payload { get; set; }

        [JsonProperty("signature")]
        public string Signature { get; set; }
    }

    public class AcmeHttpResponse
    {
        private string _ContentAsString;

        public AcmeHttpResponse(HttpWebResponse resp)
        {
            StatusCode = resp.StatusCode;
            Headers = resp.Headers;

            var rs = resp.GetResponseStream();
            using (var ms = new MemoryStream())
            {
                rs.CopyTo(ms);
                RawContent = ms.ToArray();
            }
        }

        public HttpStatusCode StatusCode
        { get; set; }

        public WebHeaderCollection Headers
        { get; set; }

        public byte[] RawContent
        { get; set; }

        public string ContentAsString
        {
            get
            {
                if (_ContentAsString == null)
                {
                    if (RawContent == null || RawContent.Length == 0)
                        return null;
                    using (var ms = new MemoryStream(RawContent))
                    {
                        using (var sr = new StreamReader(ms))
                        {
                            _ContentAsString = sr.ReadToEnd();
                        }
                    }
                }
                return _ContentAsString;
            }
        }

        public bool IsError
        { get; set; }

        public Exception Error
        { get; set; }
    }

    public class RegObject
    {
        [JsonProperty(PropertyName = "type")]
        public string type { get; set; }

        [JsonProperty(PropertyName = "status")]
        public string status { get; set; }

        [JsonProperty(PropertyName = "uri")]
        public string uri { get; set; }

        [JsonProperty(PropertyName = "token")]
        public string token { get; set; }

        [JsonProperty(PropertyName = "keyAuthorization")]
        public string keyAuthorization { get; set; }
    }

    public class Challenge
    {
        [JsonProperty(PropertyName = "type")]
        public string type { get; set; }

        [JsonProperty(PropertyName = "status")]
        public string status { get; set; }

        [JsonProperty(PropertyName = "uri")]
        public string uri { get; set; }

        [JsonProperty(PropertyName = "token")]
        public string token { get; set; }

        [JsonProperty(PropertyName = "keyAuthorization")]
        public string keyAuthorization { get; set; }

    }

    public class AuthzObject
    {
        [JsonProperty(PropertyName = "identifier")]
        public Identifier identifier { get; set; }

        [JsonProperty(PropertyName = "type")]
        public string type { get; set; }

        [JsonProperty(PropertyName = "value")]
        public string value { get; set; }

        [JsonProperty(PropertyName = "status")]
        public string status { get; set; }

        [JsonProperty(PropertyName = "expires")]
        public string expires { get; set; }

        [JsonProperty(PropertyName = "challenges")]
        public IEnumerable<Challenge> challenges { get; set; }

        [JsonProperty(PropertyName = "AuthzUri")]
        public string Uri { get; set; }

        public class Identifier
        {
            [JsonProperty("type")]
            public string Type { get; set; }

            [JsonProperty("value")]
            public string Value { get; set; }
        }
    }

    class Program
    {
        public static string nextNonce = "";

        public static void Main()
        {
            var hostname = "test.oakington.info";
            var ACCOUNT_EMAIL = "moconnore@gmail.com";



            var CA = "https://acme-v01.api.letsencrypt.org";
            //var CA = "https://acme-staging.api.letsencrypt.org";
            var TERMS = "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf";
            JObject account_pubkey = new JObject();
            JObject domain = new JObject();

            //setup folder structure
            Directory.CreateDirectory($"./domains/{hostname}/keys/");

            //generate keypair if needed 
            RSAParameters keyParams;

            if (File.Exists($"./domains/{hostname}/keys/account.key"))
            {
                StreamReader sr = new StreamReader($"./domains/{hostname}/keys/account.key");
                const String pemprivheader = "-----BEGIN RSA PRIVATE KEY-----";
                const String pemprivfooter = "-----END RSA PRIVATE KEY-----";
                string pemstr = sr.ReadToEnd();
                sr.Close();
                StringBuilder sb = new StringBuilder(pemstr);
                sb.Replace(pemprivheader, "");  //remove headers/footers, if present
                sb.Replace(pemprivfooter, "");
                String pvkstr = sb.ToString().Trim();
                RSACryptoServiceProvider rsaAccount = DecodeRSAPrivateKey(pvkstr.Base64UrlDecode());
                keyParams = rsaAccount.ExportParameters(true);
            }
            else
            {
                var rsaAccount = new RSACryptoServiceProvider(2048);
                keyParams = rsaAccount.ExportParameters(true);
                //save privkey
                var sw = new StreamWriter($"./domains/{hostname}/keys/account.key");
                ExportPrivateKey(rsaAccount, sw);
                sw.Close();
            }

            //generate JSON web-key headers
            JsonWebKey jwk = new JsonWebKey();
            jwk.KeyType = "RSA";
            jwk.Exponent = Base64UrlEncode(keyParams.Exponent);
            jwk.Modulus = Base64UrlEncode(keyParams.Modulus);

            JWSHeader header = new JWSHeader()
            {
                Algorithm = "RS256",
                Key = jwk,
            };


            //build account registration payload
            var newReg = new
            {
                resource = "new-reg",
                contact = new string[]
                {
                    "mailto:" + ACCOUNT_EMAIL,
                },
                agreement = TERMS,
            };
            //register with CA

            var message = new JWSMessage
            {
                Header = header,
                Payload = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(newReg))),
            };
            message.Protected = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(new { nonce = getNonce(CA) }, Formatting.None)));
            message.Signature = Base64UrlEncode(HashAndSignBytes(Encoding.ASCII.GetBytes(message.Protected + "." + message.Payload), keyParams));

            AcmeHttpResponse regresp = postHttpResponse(CA + "/acme/new-reg", JsonConvert.SerializeObject(message, Formatting.Indented));
            if (regresp.StatusCode == HttpStatusCode.Created)
            {
                Console.WriteLine("Successfully Registered");
                nextNonce = regresp.Headers.Get("replay-nonce");
            }
            else if (regresp.StatusCode == HttpStatusCode.Conflict)
            {
                Console.WriteLine("Already Registered");
                nextNonce = regresp.Headers.Get("replay-nonce");
            }
            else
            {
                Console.WriteLine($"Error [{regresp.StatusCode}]: {regresp.Error.Message}");
                Quit();
            }


            //get authz
            AuthzObject authzJson = null;
            Challenge http01 = null;
            bool challengecomplete = false;
            string fname = $"./domains/{hostname}/authz_{GetSha256Thumbprint(jwk)}";
            //check for prev authz
            if (File.Exists(fname))
            {
                authzJson = JsonConvert.DeserializeObject<AuthzObject>(File.ReadAllText(fname));
                foreach (var challenge in authzJson.challenges)
                {
                    if (challenge.type == "http-01")
                    {
                        //check if authz is still valid
                        var resp = getHttpResponse(authzJson.Uri);
                        AuthzObject respJson = JsonConvert.DeserializeObject<AuthzObject>(resp.ContentAsString);
                        nextNonce = resp.Headers.Get("Replay-Nonce");
                        if (respJson.status == "invalid" || respJson.status == "revoked" || respJson.status == "unknown")
                        {
                            authzJson = null;
                            File.Delete(fname); //remove expired authz
                        }
                        else if(respJson.status == "valid")
                        {
                            Console.WriteLine("We already have a valid authz. Time to get out cert.");
                            challengecomplete = true;
                        }
                    }
                }
            }
            if (authzJson == null) //expired or nonexistant previous authz for privkey.
            {
                //build authz payload
                var newAuthz = new
                {
                    resource = "new-authz",
                    identifier = new
                    {
                        type = "dns",
                        value = hostname,
                    }
                };
                //var message = new JWSMessage();
                message.Header = header;
                message.Payload = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(newAuthz)));
                message.Protected = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(new { nonce = nextNonce }, Formatting.None)));
                message.Signature = Base64UrlEncode(HashAndSignBytes(Encoding.ASCII.GetBytes(message.Protected + "." + message.Payload), keyParams));
                AcmeHttpResponse authzresp;
                authzresp = postHttpResponse(CA + "/acme/new-authz", JsonConvert.SerializeObject(message, Formatting.Indented));
                nextNonce = authzresp.Headers.Get("Replay-Nonce");
                if (authzresp.StatusCode == HttpStatusCode.Created)
                {
                    //nextNonce = authzresp.Headers.Get("replay-nonce");
                    Console.WriteLine("Got Authz Challenges");
                    Console.WriteLine(authzresp.ContentAsString);
                    //saveChallenge for later
                    authzJson = JsonConvert.DeserializeObject<AuthzObject>(authzresp.ContentAsString);
                    authzJson.Uri = authzresp.Headers.Get("Location");
                    File.WriteAllText(fname, JsonConvert.SerializeObject(authzJson));
                    //get challenge token

                }
                else
                {
                    Console.WriteLine($"Error [{authzresp.StatusCode}]: {authzresp.Error.Message} ");
                    Quit();
                }

            }
            if (challengecomplete == false)
            {
                //complete challenges
                if (authzJson == null) { Console.WriteLine("no challenges provided. Something went wrong"); Quit(); }

                //find http-01 challenge.
                foreach (var challenge in authzJson.challenges)
                {
                    if (challenge.type == "http-01") { http01 = challenge; Console.WriteLine("Received http-01 challenge"); }
                }
                if (http01 == null) { Console.WriteLine("No http-01 challenge found. That's all that is supported for now."); Quit(); }

                //complete challenge
                //host file with contents ${token}.{GetSha256Thumbprint} at {hostname}/.well-known/acme/{token}
                Console.WriteLine($"Outputing challenge file to {hostname}/.well-known/acme/{http01.token}");
                File.WriteAllText(Directory.CreateDirectory($"./domains/{hostname}/.well-known/acme-challenge").FullName + "/" + http01.token, $"{http01.token}.{GetSha256Thumbprint(jwk)}");

                //tell CA we've completed challenge
                //build challenge response payload
                var challengeResp = new
                {
                    resource = "challenge",
                    type = "http-01",
                    KeyAuthorization = $"{http01.token}.{GetSha256Thumbprint(jwk)}", //figure this out
                };
                message.Header = header;
                message.Payload = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(challengeResp)));
                message.Protected = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(new { nonce = nextNonce }, Formatting.None)));
                message.Signature = Base64UrlEncode(HashAndSignBytes(Encoding.ASCII.GetBytes(message.Protected + "." + message.Payload), keyParams));
                AcmeHttpResponse challengeHttpResp;
                challengeHttpResp = postHttpResponse(http01.uri, JsonConvert.SerializeObject(message, Formatting.Indented));
                nextNonce = challengeHttpResp.Headers.Get("Replay-Nonce");
                if (challengeHttpResp.StatusCode == HttpStatusCode.Accepted)
                {
                    Console.WriteLine("CA accepted our challenge request. Now let's wait until it verifies.");
                }
                else
                {
                    Console.WriteLine(challengeHttpResp.Error.Message);
                    Console.WriteLine(challengeHttpResp.ContentAsString);
                    Quit();
                }

                //keep polling to see if challenge has been completed
                while (!challengecomplete)
                {
                    AcmeHttpResponse resp = getHttpResponse(authzJson.Uri);
                    nextNonce = resp.Headers.Get("Replay-Nonce");
                    Challenge respJson = JsonConvert.DeserializeObject<Challenge>(resp.ContentAsString);
                    if (resp.StatusCode == HttpStatusCode.Accepted || resp.StatusCode == HttpStatusCode.OK)
                    {
                        switch (respJson.status)
                        {
                            case ("valid"):
                                Console.WriteLine("YAY. Challenge accepted. Let's get our cert.");
                                challengecomplete = true;
                                break;
                            case ("pending"):
                                Console.WriteLine("waiting for CA to verify...");
                                System.Threading.Thread.Sleep(120000);
                                break;
                            case ("invalid"):
                                Console.WriteLine("Failed challenge.");
                                break;
                        }
                    }
                }
            }



            //get certificate
            //check for existing certs
            if (File.Exists($"./domains/{hostname}/certs/cert.pfx"))
            {
                //check expiration on cert.
                Console.WriteLine("Cert found. Checking on cert age.");
                X509Certificate cert = X509Certificate.CreateFromCertFile($"./domains/{hostname}/certs/cert.pfx");
                var expiration = cert.GetExpirationDateString();
                if (DateTime.Parse(expiration).Subtract(DateTime.Now).Days < 30)
                {
                    Console.WriteLine("Cert is going to expire in < 30 days....renewing.");
                    //renew and quit.
                    AcmeHttpResponse certReq = getHttpResponse(File.ReadAllText($"./domains/{hostname}/certs/cert.uri"));
                    if (certReq.StatusCode == HttpStatusCode.OK)
                    {
                        if (certReq.ContentAsString != "")
                        {
                            cert = new X509Certificate();
                            cert.Import(certReq.RawContent);
                            File.WriteAllBytes(Directory.CreateDirectory($"./domains/{hostname}/certs").FullName + "/cert.pfx", cert.Export(X509ContentType.Pfx));
                            Console.WriteLine("SUCCESS cert renewed");
                        }
                        else
                        {
                            Console.WriteLine("Failed to renew cert");
                            Quit();
                        }
                    }
                }
                else
                {
                    Console.WriteLine("Cert is valid. Exiting.");
                    Quit();
                }
            }
            
            //build csr payload
            var csr = new
            {
                resource = "new-cert",
                csr = generateCSR(hostname),
            };
            message.Header = header;
            message.Payload = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(csr)));
            message.Protected = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(new { nonce = nextNonce }, Formatting.None)));
            message.Signature = Base64UrlEncode(HashAndSignBytes(Encoding.ASCII.GetBytes(message.Protected + "." + message.Payload), keyParams));
            AcmeHttpResponse csrHttpResp;
            csrHttpResp = postHttpResponse(CA + "/acme/new-cert", JsonConvert.SerializeObject(message, Formatting.Indented));
            if (csrHttpResp.StatusCode == HttpStatusCode.Created)
            {
                string certUri = csrHttpResp.Headers.Get("Location");
                if (csrHttpResp.ContentAsString!="")
                {
                    X509Certificate cert = new X509Certificate();
                    cert.Import(csrHttpResp.RawContent);
                    File.WriteAllBytes(Directory.CreateDirectory($"./domains/{hostname}/certs").FullName + "/cert.pfx", cert.Export(X509ContentType.Pfx));
                    File.WriteAllText($"./domains/{hostname}/certs/cert.uri",certUri);
                    Console.WriteLine("SUCCESS new cert obtained!");
                    Quit();
                }
            }
            else{Console.WriteLine($"Error [{csrHttpResp.StatusCode}]: {csrHttpResp.ContentAsString}");Quit();}

        }

        private static AcmeHttpResponse getHttpResponse(string address)
        {
            var request = (HttpWebRequest)WebRequest.Create(address);
            try
            {
                using (HttpWebResponse resp = (HttpWebResponse)request.GetResponse())
                {
                    return new AcmeHttpResponse(resp);
                }
            }
            catch (WebException ex) when (ex.Response != null)
            {
                using (var resp = (HttpWebResponse)ex.Response)
                {
                    var acmeResp = new AcmeHttpResponse(resp)
                    {
                        IsError = true,
                        Error = ex,
                    };
                    return acmeResp;
                }
            }
        }

        private static AcmeHttpResponse postHttpResponse(string address, string postData)
        {
            var data = Encoding.UTF8.GetBytes(postData);

            var request = (HttpWebRequest)WebRequest.Create(address);
            request.KeepAlive = false;
            request.AllowWriteStreamBuffering = false;
            request.AllowReadStreamBuffering = false;
            request.Method = "POST";
            request.ContentType = "application/json";
            request.ContentLength = data.Length;
            request.Timeout = 10000;
            try
            {
                using (var stream = request.GetRequestStream())
                {
                    stream.Write(data, 0, data.Length);
                }
                using (HttpWebResponse resp = (HttpWebResponse)request.GetResponse())
                {
                    return new AcmeHttpResponse(resp);
                }
            }
            catch (WebException ex) when (ex.Response != null)
            {
                using (var resp = (HttpWebResponse)ex.Response)
                {
                    var acmeResp = new AcmeHttpResponse(resp)
                    {
                        IsError = true,
                        Error = ex,
                    };
                    return acmeResp;
                }
            }
        }

        private static string generateCSR(string domain)
        {
            RSAParameters keyParams;

            if (File.Exists($"./domains/{domain}/keys/csr.key"))
            {
                StreamReader sr = new StreamReader($"./domains/{domain}/keys/csr.key");
                const String pemprivheader = "-----BEGIN RSA PRIVATE KEY-----";
                const String pemprivfooter = "-----END RSA PRIVATE KEY-----";
                string pemstr = sr.ReadToEnd();
                sr.Close();
                StringBuilder sb = new StringBuilder(pemstr);
                sb.Replace(pemprivheader, "");  //remove headers/footers, if present
                sb.Replace(pemprivfooter, "");
                String pvkstr = sb.ToString().Trim();
                RSACryptoServiceProvider rsaAccount = DecodeRSAPrivateKey(pvkstr.Base64UrlDecode());
                keyParams = rsaAccount.ExportParameters(true);
            }
            else
            {
                var rsaAccount = new RSACryptoServiceProvider(2048);
                keyParams = rsaAccount.ExportParameters(true);
                //save privkey
                var sw = new StreamWriter($"./domains/{domain}/keys/csr.key");
                ExportPrivateKey(rsaAccount, sw);
                sw.Close();
            }
            var serializer = new Asn1Serializer();
            var sut = new CertificateRequestAsn1DEREncoder(serializer);
            var data = new CertificateRequestData(domain, keyParams);
            var csr = sut.EncodeAsDER(data);
            return Base64UrlEncode(csr);
        }

        private static byte[] HashAndSignBytes(byte[] DataToSign, RSAParameters Key)
        {
            try
            {
                // Create a new instance of RSACryptoServiceProvider using the 
                // key from RSAParameters.  
                RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();
                SHA256CryptoServiceProvider sha = new SHA256CryptoServiceProvider();

                RSAalg.ImportParameters(Key);

                // Hash and sign the data. SHA256
                return RSAalg.SignData(DataToSign, sha);
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return null;
            }
        }

        private static RSACryptoServiceProvider DecodeRSAPrivateKey(byte[] privkey)
        {
            //------- Parses binary ans.1 RSA private key; returns RSACryptoServiceProvider  ---

            byte[] MODULUS, E, D, P, Q, DP, DQ, IQ;

            // ---------  Set up stream to decode the asn.1 encoded RSA private key  ------
            MemoryStream mem = new MemoryStream(privkey);
            BinaryReader binr = new BinaryReader(mem);    //wrap Memory Stream with BinaryReader for easy reading
            byte bt = 0;
            ushort twobytes = 0;
            int elems = 0;
            try
            {
                twobytes = binr.ReadUInt16();
                if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                    binr.ReadByte();        //advance 1 byte
                else if (twobytes == 0x8230)
                    binr.ReadInt16();       //advance 2 bytes
                else
                    return null;

                twobytes = binr.ReadUInt16();
                if (twobytes != 0x0102) //version number
                    return null;
                bt = binr.ReadByte();
                if (bt != 0x00)
                    return null;


                //------  all private key components are Integer sequences ----
                elems = GetIntegerSize(binr);
                MODULUS = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                E = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                D = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                P = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                Q = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                DP = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                DQ = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                IQ = binr.ReadBytes(elems);



                // ------- create RSACryptoServiceProvider instance and initialize with public key -----
                RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                RSAParameters RSAparams = new RSAParameters();
                RSAparams.Modulus = MODULUS;
                RSAparams.Exponent = E;
                RSAparams.D = D;
                RSAparams.P = P;
                RSAparams.Q = Q;
                RSAparams.DP = DP;
                RSAparams.DQ = DQ;
                RSAparams.InverseQ = IQ;
                RSA.ImportParameters(RSAparams);
                return RSA;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return null;
            }
            finally
            {
                binr.Close();
            }
        }

        private static void ExportPublicKey(RSACryptoServiceProvider csp, TextWriter outputStream)
        {
            var parameters = csp.ExportParameters(false);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    innerWriter.Write((byte)0x30); // SEQUENCE
                    EncodeLength(innerWriter, 13);
                    innerWriter.Write((byte)0x06); // OBJECT IDENTIFIER
                    var rsaEncryptionOid = new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
                    EncodeLength(innerWriter, rsaEncryptionOid.Length);
                    innerWriter.Write(rsaEncryptionOid);
                    innerWriter.Write((byte)0x05); // NULL
                    EncodeLength(innerWriter, 0);
                    innerWriter.Write((byte)0x03); // BIT STRING
                    using (var bitStringStream = new MemoryStream())
                    {
                        var bitStringWriter = new BinaryWriter(bitStringStream);
                        bitStringWriter.Write((byte)0x00); // # of unused bits
                        bitStringWriter.Write((byte)0x30); // SEQUENCE
                        using (var paramsStream = new MemoryStream())
                        {
                            var paramsWriter = new BinaryWriter(paramsStream);
                            EncodeIntegerBigEndian(paramsWriter, parameters.Modulus); // Modulus
                            EncodeIntegerBigEndian(paramsWriter, parameters.Exponent); // Exponent
                            var paramsLength = (int)paramsStream.Length;
                            EncodeLength(bitStringWriter, paramsLength);
                            bitStringWriter.Write(paramsStream.GetBuffer(), 0, paramsLength);
                        }
                        var bitStringLength = (int)bitStringStream.Length;
                        EncodeLength(innerWriter, bitStringLength);
                        innerWriter.Write(bitStringStream.GetBuffer(), 0, bitStringLength);
                    }
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                outputStream.WriteLine("-----BEGIN PUBLIC KEY-----");
                for (var i = 0; i < base64.Length; i += 64)
                {
                    outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
                }
                outputStream.WriteLine("-----END PUBLIC KEY-----");
            }
        }

        private static void ExportPrivateKey(RSACryptoServiceProvider csp, TextWriter outputStream)
        {
            if (csp.PublicOnly) throw new ArgumentException("CSP does not contain a private key", "csp");
            var parameters = csp.ExportParameters(true);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
                    EncodeIntegerBigEndian(innerWriter, parameters.Modulus);
                    EncodeIntegerBigEndian(innerWriter, parameters.Exponent);
                    EncodeIntegerBigEndian(innerWriter, parameters.D);
                    EncodeIntegerBigEndian(innerWriter, parameters.P);
                    EncodeIntegerBigEndian(innerWriter, parameters.Q);
                    EncodeIntegerBigEndian(innerWriter, parameters.DP);
                    EncodeIntegerBigEndian(innerWriter, parameters.DQ);
                    EncodeIntegerBigEndian(innerWriter, parameters.InverseQ);
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                outputStream.WriteLine("-----BEGIN RSA PRIVATE KEY-----");
                // Output as Base64 with lines chopped at 64 characters
                for (var i = 0; i < base64.Length; i += 64)
                {
                    outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
                }
                outputStream.WriteLine("-----END RSA PRIVATE KEY-----");
            }
        }

        private static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
            if (length < 0x80)
            {
                // Short form
                stream.Write((byte)length);
            }
            else
            {
                // Long form
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }
                stream.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    stream.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }

        private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
        {
            stream.Write((byte)0x02); // INTEGER
            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != 0) break;
                prefixZeros++;
            }
            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefixZeros);
                }
                for (var i = prefixZeros; i < value.Length; i++)
                {
                    stream.Write(value[i]);
                }
            }
        }

        private static int GetIntegerSize(BinaryReader binr)
        {
            byte bt = 0;
            byte lowbyte = 0x00;
            byte highbyte = 0x00;
            int count = 0;
            bt = binr.ReadByte();
            if (bt != 0x02)     //expect integer
                return 0;
            bt = binr.ReadByte();

            if (bt == 0x81)
                count = binr.ReadByte();    // data size in next byte
            else
            if (bt == 0x82)
            {
                highbyte = binr.ReadByte(); // data size in next 2 bytes
                lowbyte = binr.ReadByte();
                byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
                count = BitConverter.ToInt32(modint, 0);
            }
            else
            {
                count = bt;     // we already have the data size
            }



            while (binr.ReadByte() == 0x00)
            {   //remove high order zeros in data
                count -= 1;
            }
            binr.BaseStream.Seek(-1, SeekOrigin.Current);       //last ReadByte wasn't a removed zero, so back up a byte
            return count;
        }

        private static string Base64UrlEncode(byte[] raw)
        {
            string enc = Convert.ToBase64String(raw);  // Regular base64 encoder
            enc = enc.Split('=')[0];                   // Remove any trailing '='s
            enc = enc.Replace('+', '-');               // 62nd char of encoding
            enc = enc.Replace('/', '_');               // 63rd char of encoding
            return enc;
        }

        private static string cacheBuster()
        {
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            byte[] rand = new byte[8];
            rngCsp.GetBytes(rand);
            return "?cachebuster=" + System.Text.Encoding.UTF8.GetString(rand);
        }

        private static string getNonce(string CA)
        {
            AcmeHttpResponse resp = getHttpResponse(CA + "/directory" + cacheBuster());
            WebHeaderCollection headers = resp.Headers;
            string nonce = headers.Get("Replay-Nonce");
            return nonce;
        }

        private static string GetSha256Thumbprint(JsonWebKey jwk)
        {
            var json = "{\"e\":\"" + jwk.Exponent + "\",\"kty\":\"RSA\",\"n\":\"" + jwk.Modulus + "\"}";
            var sha256 = SHA256.Create();
            return Base64UrlEncode(sha256.ComputeHash(Encoding.UTF8.GetBytes(json)));
        }

        private static void Quit()
        {
            Console.WriteLine("Press enter to quit.");
            Console.ReadLine();
            Environment.Exit(1);
        }
    }
    
}
