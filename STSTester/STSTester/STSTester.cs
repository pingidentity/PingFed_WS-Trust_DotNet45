using System;
using System.IdentityModel.Tokens;
using System.IdentityModel.Protocols.WSTrust;
using System.IO;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Security;
using System.Xml;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Channels;
using System.Security.Claims;

namespace com.pingidentity.pmeyer.wstrust
{
    class STSTester
    {
        //String tokenType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1";
        public static String tokenType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";

        public static String IPSTS_appliesTo = "https://localhost/wcftest"; // This is the AppliesTo value for the RST - corresponds to the "Partner Service Identifier" value in PF
        public static String RPSTS_appliesTo = "wcftest:wstrust:rp"; // When we request a local token from the RP-STS this looks up the client (Virtual Server ID form the WS-Trust IDP connection)

        // These are the PingFederate STS endpoints
        public static String PF_Base_URL = "https://localhost:9031";
        public static String PF_TokenExchange_Endpoint = PF_Base_URL + "/pf/sts.wst";
        public static String PF_IP_STS_Endpoint = PF_Base_URL + "/idp/sts.wst";
        public static String PF_RP_STS_Endpoint = PF_Base_URL + "/sp/sts.wst";
        public static String PF_Signing_Cert_Thumbprint = "99076EEF3203490BC1C49CFC3D9BB3BD4A613C1A"; // Should be imported into the Computer's Personal cert store

        // Configure "default" username and passwords for username token's
        public static String proxy_username = "joe";
        public static String proxy_password = "2Federate";
        public static String subject_username = "sarah";
        public static String subject_password = "2Federate";

        public static X509Certificate2 x509Cert = new X509Certificate2("c:\\x509cert.p12", "2Federate");


        static void Main(string[] args)
        {
            Console.SetWindowSize(Console.LargestWindowWidth / 2, Console.LargestWindowHeight / 2);

            Console.WriteLine("Requesting security token from \"{0}\" for resource \"{1}\"...", PF_IP_STS_Endpoint, IPSTS_appliesTo);
            Console.WriteLine();

            try
            {
                // To Issue the initial token (ie the Web Services Client (WSC) doing its thing, we are going to auth with a username and a password

                // Issue the initial SAML token
                RequestSecurityTokenResponse RSTR_Issue;
                SecurityToken token = IssueTokenWithUserNamePassword(subject_username, subject_password, PF_IP_STS_Endpoint, IPSTS_appliesTo, out RSTR_Issue, KeyTypes.Bearer);

                // When using Asymmetric Key (HoK) - we need to supply a UseKey
                // When using Symmetric Key (HoK) - SP Encryption cert is not defined - unless encryption key available to use as subj confirmation

                if (token != null)
                {
                    //show the token
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("{0}", token);
                    Console.WriteLine();
                    Console.WriteLine("{0}", RSTR_Issue.RequestedSecurityToken.SecurityTokenXml.InnerXml);
                    Console.WriteLine();

                    // At this point we received a token from our STS.  We can now use it to authenticate to our web service using it as an IssuedToken.
                    // ... here is where the WSP kicks in...
                    //
                    Console.ForegroundColor = ConsoleColor.Gray;
                    Console.WriteLine();
                    Console.WriteLine("Do you want to validate the security token? [Y]");

                    if (Console.ReadKey(true).Key == ConsoleKey.Y)
                    {
                        Console.WriteLine("Validating security token with \"{0}\"...", PF_RP_STS_Endpoint);
                        Console.WriteLine();

                        // We are acting as the WSP now.  We want to Validate the SAML token against PingFederate's STS
                        RequestSecurityTokenResponse RSTR_Validate = ValidateSecurityToken(token, PF_RP_STS_Endpoint);

                        // This will return:
                        // http://docs.oasis-open.org/ws-sx/ws-trust/200512/status/valid or
                        // http://docs.oasis-open.org/ws-sx/ws-trust/200512/status/invalid
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("{0}", RSTR_Validate.Status.Code);
                        Console.WriteLine();

                        // So we have a valid token supplied by the web services client.... we can grab the claims from there and do as we wish... or.. we can issue a local token
                        Console.ForegroundColor = ConsoleColor.Gray;
                        Console.WriteLine();
                        Console.WriteLine("Do you want to issue a local security token? [Y]");

                        if (Console.ReadKey(true).Key == ConsoleKey.Y)
                        {
                            Console.WriteLine("Requesting \"{0}\" security token from \"{1}\"...", tokenType, PF_RP_STS_Endpoint);
                            Console.WriteLine();

                            // We need to make a call to our RP-STS (SP side of PF) to issue a local token (according to our Token Generator)
                            //SecurityToken localToken = IssueLocalSecurityToken(token, RPSTS_issuerUri, RPSTS_appliesTo, tokenType, keyType);

                            // I'm going to receive it as a GenericXmlSecurityToken so we can parse it easier later on...
                            RequestSecurityTokenResponse RSTR_LocalToken;
                            GenericXmlSecurityToken xmlToken = (GenericXmlSecurityToken)IssueLocalSecurityToken(token, PF_RP_STS_Endpoint, tokenType, out RSTR_LocalToken);
                            
                            if (xmlToken != null)
                            {
                                //show the token
                                Console.ForegroundColor = ConsoleColor.Green;
                                Console.WriteLine("{0}", xmlToken);

                                // parse token to grab the attributes:
                                if (tokenType == "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0")
                                {

                                    // Configure the IssuerNameRegistry
                                    ConfigurationBasedIssuerNameRegistry myIssuerNameRegistry = new ConfigurationBasedIssuerNameRegistry();
                                    myIssuerNameRegistry.AddTrustedIssuer(PF_Signing_Cert_Thumbprint, "RP-STS"); // this is the dsig cert (of my RP-STS) SHA1 thumbprint | name
                                    //inr.AddTrustedIssuer("97463668CD4482AFAC7F341A1C3ABB1010757800", "localhost"); // this is the encryption cert (of my RP-STS - bearer token isn't encrypted tho)

                                    // Define the "verification configuration"
                                    SecurityTokenHandlerConfiguration securityTokenHanderConfig = new SecurityTokenHandlerConfiguration();
                                    securityTokenHanderConfig.AudienceRestriction.AllowedAudienceUris.Add(new Uri("https://www.app.com")); // the Audience defined in the Token Generator
                                    Saml2SecurityTokenHandler saml2TokenHandler = new Saml2SecurityTokenHandler();
                                    securityTokenHanderConfig.IssuerNameRegistry = myIssuerNameRegistry;
                                    saml2TokenHandler.Configuration = securityTokenHanderConfig;

                                    // Parse the token and return a Claims Identity
                                    SecurityToken saml2Token = saml2TokenHandler.ReadToken(new XmlTextReader(new StringReader(xmlToken.TokenXml.OuterXml)));
                                    ClaimsIdentity identity = saml2TokenHandler.ValidateToken(saml2Token).First();

                                    // Spit out the Claims
                                    Console.WriteLine("Attributes in the Assertion.....");
                                    Console.WriteLine("{0}", identity.Name);
                                    foreach (Claim theClaim in identity.Claims)
                                    {
                                        Console.WriteLine("{0} : {1}", theClaim.Type, theClaim.Value);
                                    }
                                }
                                else if (tokenType == "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0")
                                {

                                }

                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                ConsoleColor PreviousColor = Console.ForegroundColor;

                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(ex.Message);

                if (ex.InnerException != null)
                {
                    Console.WriteLine();
                    Console.WriteLine(ex.InnerException.Message);
                }

                Console.ForegroundColor = PreviousColor;
            }

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine("Press <enter> to close.");
            Console.Read();
        }

        private static SecurityToken IssueTokenWithUserNamePassword(string username, string password, string issuerUri, string appliesTo, out RequestSecurityTokenResponse RSTR, string keyType = KeyTypes.Bearer)
        {
            if (String.IsNullOrWhiteSpace(issuerUri)) throw new ArgumentNullException("issuerUri");
            if (String.IsNullOrWhiteSpace(appliesTo)) throw new ArgumentNullException("appliesTo");

            Binding binding = null;
            var WsHttpBinding = new WS2007HttpBinding(SecurityMode.TransportWithMessageCredential);

            // Avoid the WS-SecureConversation piece
            WsHttpBinding.Security.Message.EstablishSecurityContext = false;
            WsHttpBinding.Security.Message.NegotiateServiceCredential = false;
            WsHttpBinding.Security.Message.ClientCredentialType = MessageCredentialType.UserName;

            // Set our binding variable
            binding = WsHttpBinding;

            // Define the STS endpoint
            EndpointAddress endpoint = new EndpointAddress(new Uri(issuerUri));

            var factory = new WSTrustChannelFactory(binding, endpoint) { TrustVersion = TrustVersion.WSTrust13 };

            // Here is where we set the credentials (goes into the SOAP security header)
            factory.Credentials.SupportInteractive = false; // Avoid that CardSpace popup...
            factory.Credentials.UserName.UserName = username;
            factory.Credentials.UserName.Password = password;

            SecurityTokenElement OnBehalfOfElement = new SecurityTokenElement(new UserNameSecurityToken("pbell", "2Federate"));
            SecurityTokenElement ActAsElement = new SecurityTokenElement(new UserNameSecurityToken("mpavlich", "2Federate"));

            // Now we define the Request for Security Token (RST)
            RequestSecurityToken RST = new RequestSecurityToken()
            {
                //identifiy who this token is for
                AppliesTo = new EndpointReference(appliesTo),
                //identify what type of request this is (Issue or Validate)
                RequestType = RequestTypes.Issue,
                //set the keytype (symmetric, asymmetric (pub key) or bearer)
                KeyType = keyType
            };

            // Create the WS-Trust channel
            IWSTrustChannelContract channel = factory.CreateChannel();

            // Send the Issue RST request
            SecurityToken token = channel.Issue(RST, out RSTR);

            return token;
        }

        private static RequestSecurityTokenResponse ValidateSecurityToken(SecurityToken foreignToken, string RP_Endpoint, string keyType = KeyTypes.Bearer)
        {
            if (String.IsNullOrWhiteSpace(RP_Endpoint)) throw new ArgumentNullException("RP_Endpoint");

            Binding binding = null;

            // Using a SAML bearer token
            var WsHttpBinding = new WS2007FederationHttpBinding(WSFederationHttpSecurityMode.TransportWithMessageCredential);
            WsHttpBinding.Security.Message.EstablishSecurityContext = false;
            WsHttpBinding.Security.Message.NegotiateServiceCredential = false;
            WsHttpBinding.Security.Message.IssuedKeyType = SecurityKeyType.BearerKey;
            binding = WsHttpBinding;

            // Define the STS endpoint
            EndpointAddress endpoint = new EndpointAddress(new Uri(RP_Endpoint));

            var factory = new WSTrustChannelFactory(binding, endpoint) { TrustVersion = TrustVersion.WSTrust13 };
            factory.Credentials.SupportInteractive = false; // Avoid that CardSpace popup...
            IWSTrustChannelContract channel = factory.CreateChannelWithIssuedToken(foreignToken); // When we create the Channel we specify the SAML token received from the WSC

            // Build the RST
            RequestSecurityToken RST = new RequestSecurityToken()
            {
                //identify what type of request this is (Issue or Validate)
                RequestType = RequestTypes.Validate
            };

            // Send the Validate RST
            RequestSecurityTokenResponse RSTR = channel.Validate(RST);

            return RSTR;
        }

        private static SecurityToken IssueLocalSecurityToken(SecurityToken foreignToken, string RP_Endpoint, string appliesTo, out RequestSecurityTokenResponse RSTR, string keyType = KeyTypes.Bearer)
        {
            if (String.IsNullOrWhiteSpace(RP_Endpoint)) throw new ArgumentNullException("RP_Endpoint");

            Binding binding = null;

            // Authenticate with a SAML Bearer token
            var WsHttpBinding = new WS2007FederationHttpBinding(WSFederationHttpSecurityMode.TransportWithMessageCredential);
            WsHttpBinding.Security.Message.EstablishSecurityContext = false;
            WsHttpBinding.Security.Message.NegotiateServiceCredential = false;
            WsHttpBinding.Security.Message.IssuedKeyType = SecurityKeyType.BearerKey;
            binding = WsHttpBinding;

            // Define the STS endpoint
            EndpointAddress endpoint = new EndpointAddress(new Uri(RP_Endpoint));

            var factory = new WSTrustChannelFactory(binding, endpoint) { TrustVersion = TrustVersion.WSTrust13 };
            factory.Credentials.SupportInteractive = false; // avoid that Cardspace dialog

            // Now we define the Request for Security Token (RST)
            RequestSecurityToken RST = new RequestSecurityToken()
            {
                //identifiy which local token we want
                AppliesTo = new EndpointReference(appliesTo),
                //identify what type of request this is (Issue or Validate)
                RequestType = RequestTypes.Issue,
                //set what kind of token we want returned (appliesTo will override this)
                TokenType = tokenType,
                //set the keytype (symmetric, asymmetric (pub key) or bearer - null = Sender Vouches)
                KeyType = null
            };

            //create the channel (using the SAML token received from the WSC)
            IWSTrustChannelContract channel = factory.CreateChannelWithIssuedToken(foreignToken);

            //send the token issuance command
            SecurityToken token = channel.Issue(RST, out RSTR);

            return token;
        }
    }
}
