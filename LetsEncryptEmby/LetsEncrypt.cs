using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Text;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json;
using Oocx.Asn1PKCS.PKCS10;
using Oocx.Asn1PKCS.Asn1BaseTypes;
using System.Runtime.InteropServices;

namespace MediaBrowser.ServerApplication.Networking
{
    internal class LetsEncrypt
    {
        //static string CA = "https://acme-v01.api.letsencrypt.org";
        static string CA = "https://acme-staging.api.letsencrypt.org";
        static string TERMS = "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf";
        static string nextNonce;
        static string sslDir;

        internal static void GetCert(string sslPath, string hostname, string email)
        {
            sslDir = sslPath;
            Register(email);
            AuthzObject auth = Authz(hostname, email);
            if (auth == null) { return; }
            completeChallenge(auth);
            downloadCertificate(hostname);
        }

        public static void RenewCert(string sslpath, string email)
        {
            //get certificate
            //check for existing certs
            if (File.Exists(sslpath + "/certs/cert.pfx"))
            {
                //check expiration on cert.
                Console.WriteLine("Cert found. Checking expiration date.");
                X509Certificate origCert = X509Certificate.CreateFromCertFile(sslpath + "/certs/cert.pfx");

                var expiration = origCert.GetExpirationDateString();
                if (DateTime.Parse(expiration).Subtract(DateTime.Now).Days < 30)
                {
                    Console.WriteLine("Cert is going to expire in < 30 days....renewing.");
                    //renew and quit.
                    AcmeHttpResponse certReq = getHttpResponse(File.ReadAllText(sslpath + "/certs/cert.uri"));
                    if (certReq.StatusCode == HttpStatusCode.OK)
                    {
                        if (certReq.ContentAsString != "")
                        {
                            X509Certificate2 newCert = new X509Certificate2();
                            newCert.Import(certReq.RawContent);
                            StreamReader sr = new StreamReader(sslpath + "/keys/csr.key");
                            const String pemprivheader = "-----BEGIN RSA PRIVATE KEY-----";
                            const String pemprivfooter = "-----END RSA PRIVATE KEY-----";
                            string pemstr = sr.ReadToEnd();
                            sr.Close();
                            StringBuilder sb = new StringBuilder(pemstr);
                            sb.Replace(pemprivheader, "");  //remove headers/footers, if present
                            sb.Replace(pemprivfooter, "");
                            String pvkstr = sb.ToString().Trim();
                            RSACryptoServiceProvider rsaAccount = DecodeRSAPrivateKey(pvkstr.Base64UrlDecode());
                            newCert.PrivateKey = rsaAccount;
                            File.WriteAllBytes(Directory.CreateDirectory(sslpath + "/certs").FullName + "/cert.pfx", newCert.Export(X509ContentType.Pfx));
                            Console.WriteLine("SUCCESS cert renewed");
                        }
                        else
                        {
                            Console.WriteLine("Failed to renew cert");
                            return;
                        }
                    }
                }
            }

        }

        private static void Register(string email)
        {
            //build account registration payload
            var newReg = new
            {
                resource = "new-reg",
                contact = new string[]
                {
                    "mailto:" + email,
                },
                agreement = TERMS,
            };
            //register with CA

            var message = new JWSMessage
            {
                Header = getHeader(),
                Payload = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(newReg))),
            };
            message.Protected = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(new { nonce = getNonce(CA) }, Formatting.None)));
            message.Signature = Base64UrlEncode(HashAndSignBytes(Encoding.ASCII.GetBytes(message.Protected + "." + message.Payload), getKeyParams()));

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
        }

        private static AuthzObject Authz(string hostname, string email)
        {
            //get authz
            AuthzObject authzJson = null;
            string fname = sslDir + $"/authz_{GetSha256Thumbprint(getJWK())}";
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
                var message = new JWSMessage();
                message.Header = getHeader();
                message.Payload = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(newAuthz)));
                message.Protected = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(new { nonce = nextNonce }, Formatting.None)));
                message.Signature = Base64UrlEncode(HashAndSignBytes(Encoding.ASCII.GetBytes(message.Protected + "." + message.Payload), getKeyParams()));
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

            }
            return authzJson;
        }

        private static void completeChallenge(AuthzObject authzJson)
        {
            //find http-01 challenge.
            Challenge http01 = null;
            foreach (var challenge in authzJson.challenges)
            {
                if (challenge.type == "http-01")
                {
                    http01 = challenge;
                    Console.WriteLine("Received http-01 challenge");
                }
            }
            if (http01 == null)
            {
                return;
            }
            if (http01.status == "valid")
            {
                return;
            }

            //complete challenge
            //host file with contents ${token}.{GetSha256Thumbprint} at {hostname}/.well-known/acme/{token}
            Console.WriteLine($"Outputing challenge file to {sslDir}/.well-known/acme/{http01.token}");
            File.WriteAllText(Directory.CreateDirectory(sslDir + "/.well-known/acme-challenge").FullName + "/" + http01.token, $"{http01.token}.{GetSha256Thumbprint(getJWK())}");


            //host file on :80 now


            SimpleHTTPServer myServer = new SimpleHTTPServer(sslDir, 80);
            //tell CA we've completed challenge
            //build challenge response payload
            var challengeResp = new
            {
                resource = "challenge",
                type = "http-01",
                KeyAuthorization = $"{http01.token}.{GetSha256Thumbprint(getJWK())}",
            };
            var message = new JWSMessage();
            message.Header = getHeader();
            message.Payload = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(challengeResp)));
            message.Protected = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(new { nonce = nextNonce }, Formatting.None)));
            message.Signature = Base64UrlEncode(HashAndSignBytes(Encoding.ASCII.GetBytes(message.Protected + "." + message.Payload), getKeyParams()));
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
                //return?
            }

            //keep polling to see if challenge has been completed
            bool challengecomplete = false;
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
                            myServer.Stop();
                            break;
                        case ("pending"):
                            Console.WriteLine("waiting for CA to verify...");
                            Thread.Sleep(10000);
                            break;
                        case ("invalid"):
                            Console.WriteLine("Failed challenge.");
                            Console.WriteLine(resp.ContentAsString);
                            myServer.Stop();
                            Quit();
                            break;
                    }
                }
            }
        }

        private static void downloadCertificate(string hostname)
        {
            //build csr payload
            var csr = new
            {
                resource = "new-cert",
                csr = generateCSR(hostname),
            };
            var message = new JWSMessage();
            message.Header = getHeader();
            message.Payload = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(csr)));
            message.Protected = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(new { nonce = nextNonce }, Formatting.None)));
            message.Signature = Base64UrlEncode(HashAndSignBytes(Encoding.ASCII.GetBytes(message.Protected + "." + message.Payload), getKeyParams()));
            AcmeHttpResponse csrHttpResp;
            csrHttpResp = postHttpResponse(CA + "/acme/new-cert", JsonConvert.SerializeObject(message, Formatting.Indented));
            if (csrHttpResp.StatusCode == HttpStatusCode.Created)
            {
                string certUri = csrHttpResp.Headers.Get("Location");
                if (csrHttpResp.ContentAsString != "")
                {
                    StreamReader sr = new StreamReader(sslDir + "/keys/csr.key");
                    const String pemprivheader = "-----BEGIN RSA PRIVATE KEY-----";
                    const String pemprivfooter = "-----END RSA PRIVATE KEY-----";
                    string pemstr = sr.ReadToEnd();
                    sr.Close();
                    StringBuilder sb = new StringBuilder(pemstr);
                    sb.Replace(pemprivheader, "");  //remove headers/footers, if present
                    sb.Replace(pemprivfooter, "");
                    String pvkstr = sb.ToString().Trim();
                    RSACryptoServiceProvider rsaAccount =  DecodeRSAPrivateKey(pvkstr.Base64UrlDecode());
                    rsaAccount.PersistKeyInCsp = true;
                    X509Certificate2 newCert = new X509Certificate2(csrHttpResp.RawContent,"",X509KeyStorageFlags.PersistKeySet)
                    {
                        PrivateKey = rsaAccount
                    };
                    File.WriteAllBytes(Directory.CreateDirectory(sslDir + "/certs").FullName + "/cert.pfx", newCert.Export(X509ContentType.Pkcs12));
                    File.WriteAllText(sslDir + "/certs/cert.uri", certUri);
                    Console.WriteLine("SUCCESS new cert obtained!");
                    Quit();
                }
            }
            else { Console.WriteLine($"Error [{csrHttpResp.StatusCode}]: {csrHttpResp.ContentAsString}"); Quit(); }
        }

        private static JWSHeader getHeader()
        {
            JWSHeader header = new JWSHeader()
            {
                Algorithm = "RS256",
                Key = getJWK(),
            };
            return header;
        }

        private static JsonWebKey getJWK()
        {
            RSAParameters keyParams = getKeyParams();
            //generate JSON web-key headers
            JsonWebKey jwk = new JsonWebKey();
            jwk.KeyType = "RSA";
            jwk.Exponent = Base64UrlEncode(keyParams.Exponent);
            jwk.Modulus = Base64UrlEncode(keyParams.Modulus);
            return jwk;
        }

        private static RSAParameters getKeyParams()
        {
            //setup folder structure
            Directory.CreateDirectory(sslDir + "/keys/");
            //generate keypair if needed 
            RSAParameters keyParams;

            if (File.Exists(sslDir + "/keys/account.key"))
            {
                StreamReader sr = new StreamReader(sslDir + "/keys/account.key");
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
                var sw = new StreamWriter(sslDir + "/keys/account.key");
                ExportPrivateKey(rsaAccount, sw);
                sw.Close();
            }
            return keyParams;
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

        private static string generateCSR(string hostname)
        {
            RSAParameters keyParams;

            if (File.Exists(sslDir + "/keys/csr.key"))
            {
                StreamReader sr = new StreamReader(sslDir + "/keys/csr.key");
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
                var sw = new StreamWriter(sslDir + "/keys/csr.key");
                ExportPrivateKey(rsaAccount, sw);
                sw.Close();
            }
            var serializer = new Asn1Serializer();
            var sut = new CertificateRequestAsn1DEREncoder(serializer);
            var data = new CertificateRequestData(hostname, keyParams);
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
                CspParameters Params = new CspParameters();
                Params.KeyContainerName = "KeyContainer";
                RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(Params);
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
            //Console.WriteLine("Press enter to quit.");
            //Console.ReadLine();
            //Environment.Exit(1);
        }

        private class JsonWebKey
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

        private class JWSHeader
        {

            [JsonProperty("alg")]
            public string Algorithm { get; set; }

            [JsonProperty("jwk")]
            public JsonWebKey Key { get; set; }

        }

        private class JWSMessage
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

        private class AcmeHttpResponse
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

        private class RegObject
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

        private class Challenge
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

        private class AuthzObject
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

        class SimpleHTTPServer
        {
            private readonly string[] _indexFiles = {
        "index.html",
        "index.htm",
        "default.html",
        "default.htm"
    };

            private static IDictionary<string, string> _mimeTypeMappings = new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase) {
        #region extension to MIME type list
        {".asf", "video/x-ms-asf"},
        {".asx", "video/x-ms-asf"},
        {".avi", "video/x-msvideo"},
        {".bin", "application/octet-stream"},
        {".cco", "application/x-cocoa"},
        {".crt", "application/x-x509-ca-cert"},
        {".css", "text/css"},
        {".deb", "application/octet-stream"},
        {".der", "application/x-x509-ca-cert"},
        {".dll", "application/octet-stream"},
        {".dmg", "application/octet-stream"},
        {".ear", "application/java-archive"},
        {".eot", "application/octet-stream"},
        {".exe", "application/octet-stream"},
        {".flv", "video/x-flv"},
        {".gif", "image/gif"},
        {".hqx", "application/mac-binhex40"},
        {".htc", "text/x-component"},
        {".htm", "text/html"},
        {".html", "text/html"},
        {".ico", "image/x-icon"},
        {".img", "application/octet-stream"},
        {".iso", "application/octet-stream"},
        {".jar", "application/java-archive"},
        {".jardiff", "application/x-java-archive-diff"},
        {".jng", "image/x-jng"},
        {".jnlp", "application/x-java-jnlp-file"},
        {".jpeg", "image/jpeg"},
        {".jpg", "image/jpeg"},
        {".js", "application/x-javascript"},
        {".mml", "text/mathml"},
        {".mng", "video/x-mng"},
        {".mov", "video/quicktime"},
        {".mp3", "audio/mpeg"},
        {".mpeg", "video/mpeg"},
        {".mpg", "video/mpeg"},
        {".msi", "application/octet-stream"},
        {".msm", "application/octet-stream"},
        {".msp", "application/octet-stream"},
        {".pdb", "application/x-pilot"},
        {".pdf", "application/pdf"},
        {".pem", "application/x-x509-ca-cert"},
        {".pl", "application/x-perl"},
        {".pm", "application/x-perl"},
        {".png", "image/png"},
        {".prc", "application/x-pilot"},
        {".ra", "audio/x-realaudio"},
        {".rar", "application/x-rar-compressed"},
        {".rpm", "application/x-redhat-package-manager"},
        {".rss", "text/xml"},
        {".run", "application/x-makeself"},
        {".sea", "application/x-sea"},
        {".shtml", "text/html"},
        {".sit", "application/x-stuffit"},
        {".swf", "application/x-shockwave-flash"},
        {".tcl", "application/x-tcl"},
        {".tk", "application/x-tcl"},
        {".txt", "text/plain"},
        {".war", "application/java-archive"},
        {".wbmp", "image/vnd.wap.wbmp"},
        {".wmv", "video/x-ms-wmv"},
        {".xml", "text/xml"},
        {".xpi", "application/x-xpinstall"},
        {".zip", "application/zip"},
        #endregion
    };
            private Thread _serverThread;
            private string _rootDirectory;
            private HttpListener _listener;
            private int _port;

            public int Port
            {
                get { return _port; }
                private set { }
            }

            /// <summary>
            /// Construct server with given port.
            /// </summary>
            /// <param name="path">Directory path to serve.</param>
            /// <param name="port">Port of the server.</param>
            public SimpleHTTPServer(string path, int port)
            {
                this.Initialize(path, port);
            }

            /// <summary>
            /// Construct server with suitable port.
            /// </summary>
            /// <param name="path">Directory path to serve.</param>
            public SimpleHTTPServer(string path)
            {
                //get an empty port
                TcpListener l = new TcpListener(IPAddress.Loopback, 0);
                l.Start();
                int port = ((IPEndPoint)l.LocalEndpoint).Port;
                l.Stop();
                this.Initialize(path, port);
            }

            /// <summary>
            /// Stop server and dispose all functions.
            /// </summary>
            public void Stop()
            {
                _serverThread.Abort();
                _listener.Stop();
                //remove urlacl perms
                var proc1 = new System.Diagnostics.ProcessStartInfo();
                proc1.UseShellExecute = true;
                proc1.WorkingDirectory = @"C:\Windows\System32";
                proc1.FileName = @"C:\Windows\System32\cmd.exe";
                proc1.Verb = "runas";
                proc1.Arguments = "/c " + $"netsh http delete urlacl url=http://+:80/.well-known/acme-challenge/";
                proc1.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
                System.Diagnostics.Process.Start(proc1);
            }

            private void Listen()
            {
                _listener = new HttpListener();
                _listener.Prefixes.Add("http://+:" + _port.ToString() + "/.well-known/acme-challenge/");
                _listener.Start();
                while (true)
                {
                    try
                    {
                        HttpListenerContext context = _listener.GetContext();
                        Process(context);
                    }
                    catch (Exception ex)
                    {

                    }
                }
            }

            private void Process(HttpListenerContext context)
            {
                string filename = context.Request.Url.AbsolutePath;
                Console.WriteLine(filename);
                filename = filename.Substring(1);

                if (string.IsNullOrEmpty(filename))
                {
                    foreach (string indexFile in _indexFiles)
                    {
                        if (File.Exists(Path.Combine(_rootDirectory, indexFile)))
                        {
                            filename = indexFile;
                            break;
                        }
                    }
                }

                filename = Path.Combine(_rootDirectory, filename);

                if (File.Exists(filename))
                {
                    try
                    {
                        Stream input = new FileStream(filename, FileMode.Open);

                        //Adding permanent http response headers
                        string mime;
                        context.Response.ContentType = _mimeTypeMappings.TryGetValue(Path.GetExtension(filename), out mime) ? mime : "application/octet-stream";
                        context.Response.ContentLength64 = input.Length;
                        context.Response.AddHeader("Date", DateTime.Now.ToString("r"));
                        context.Response.AddHeader("Last-Modified", System.IO.File.GetLastWriteTime(filename).ToString("r"));

                        byte[] buffer = new byte[1024 * 16];
                        int nbytes;
                        while ((nbytes = input.Read(buffer, 0, buffer.Length)) > 0)
                            context.Response.OutputStream.Write(buffer, 0, nbytes);
                        input.Close();
                        context.Response.OutputStream.Flush();

                        context.Response.StatusCode = (int)HttpStatusCode.OK;
                    }
                    catch (Exception ex)
                    {
                        context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                    }

                }
                else
                {
                    context.Response.StatusCode = (int)HttpStatusCode.NotFound;
                }

                context.Response.OutputStream.Close();
            }

            private void Initialize(string path, int port)
            {
                //grant permissions for urlacl
                var proc1 = new System.Diagnostics.ProcessStartInfo();
                proc1.UseShellExecute = true;
                proc1.WorkingDirectory = @"C:\Windows\System32";
                proc1.FileName = @"C:\Windows\System32\cmd.exe";
                proc1.Verb = "runas";
                proc1.Arguments = "/c " + $"netsh http add urlacl url=http://+:80/.well-known/acme-challenge/ user={System.Environment.UserDomainName}\\{System.Environment.UserName}";
                proc1.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
                System.Diagnostics.Process.Start(proc1);
                //sleep for 500ms to allow urlacl changes to propogate.
                Thread.Sleep(500);
                this._rootDirectory = path;
                this._port = port;
                _serverThread = new Thread(this.Listen);
                _serverThread.Start();
            }


        }
    }


}
