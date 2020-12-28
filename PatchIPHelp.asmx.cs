using System;
using System.Collections;
using System.ComponentModel;
using System.Data;
using System.Linq;
using System.Web;
using System.Web.Services;
using System.Web.Services.Protocols;
using System.Xml.Linq;
using System.Net;
using System.Text;
using System.IO;
using System.Reflection;
using System.IO.Compression;
using System.Configuration;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using System.Text.RegularExpressions;
//using SitaServices.Sws;
using System.Xml;
//using CyberPlatOpenSSL;
using RestSharp;

namespace IPHelp
{
    /// <summary>
    /// Summary description for Service1
    /// intScrapTimeout is hard coded in Riya G9
    /// 
    /// </summary>
    [WebService(Namespace = "http://tempuri.org/")]
    [WebServiceBinding(ConformsTo = WsiProfiles.BasicProfile1_1)]
    [ToolboxItem(false)]
    // To allow this Web Service to be called from script, using ASP.NET AJAX, uncomment the following line. 
    // [System.Web.Script.Services.ScriptService]
    public class PatchIPHelp : System.Web.Services.WebService
    {

        #region Specials Amadeus
        [WebMethod(Description = "Send Request For Amadeus V2.0")]
        public string[] AmadeusSendQueryV2Post(string pstrAgentId, string pstrUserId, string pstrTrackId,
                                         string pstrUrlV2, string pstrWsap, string pstrCredentials,
                                         string pstrRequestquery, string pstrAccessUrl, int pstrTimeOut)
        {
            string[] rstr_ParseResult = new string[4];
            try
            {
                HttpWebRequest webRequest = (HttpWebRequest)HttpWebRequest.Create(pstrUrlV2);
                string strFinalQuery = string.Empty;
                webRequest.Credentials = CredentialCache.DefaultNetworkCredentials;
                string[] strArrCredentials = pstrCredentials.Split('/');
                webRequest.Proxy = null;
                webRequest.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
                webRequest.Method = "POST";
                if (pstrTimeOut != -1)
                {
                    webRequest.Timeout = pstrTimeOut;
                }
                webRequest.ContentType = "text/xml; charset=utf-8";
                webRequest.Headers.Add("SOAPAction:\"http://webservices.amadeus.com/" + pstrUrlV2 + "/" + pstrAccessUrl + "\""); ;
                strFinalQuery = "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">";
                strFinalQuery += "<s:Header>";

                if (pstrAccessUrl.Contains("VLSSLQ_06_1_1A"))
                {
                    strFinalQuery += "<aws:SessionId xmlns:aws=\"http://webservices.amadeus.com/definitions\"></aws:SessionId>";
                }
                else
                {
                    strFinalQuery += "<s:Session>";
                    strFinalQuery += "<awsec:SessionId xmlns:awsec=\"http://webservices.amadeus.com/definitions\">" + strArrCredentials[0].ToString() + "</awsec:SessionId>";
                    strFinalQuery += "<awsec:SequenceNumber xmlns:awsec=\"http://webservices.amadeus.com/definitions\">" + strArrCredentials[2].ToString() + "</awsec:SequenceNumber>";
                    strFinalQuery += "<awsec:SecurityToken xmlns:awsec=\"http://webservices.amadeus.com/definitions\">" + strArrCredentials[1].ToString() + "</awsec:SecurityToken>";
                    strFinalQuery += "</s:Session>";
                }
                strFinalQuery += "</s:Header>";
                strFinalQuery += "<s:Body xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">";
                strFinalQuery += pstrRequestquery;
                strFinalQuery += "</s:Body>";
                strFinalQuery += "</s:Envelope>";
                byte[] queryByte = Convertbyte(strFinalQuery, Encoding.UTF8.GetEncoder());
                webRequest.ContentLength = queryByte.Length;

                Stream strmRequestStream;
                try
                {
                    strmRequestStream = webRequest.GetRequestStream();
                }
                catch (Exception ex)
                {
                    if (ex.InnerException != null)
                    {
                        rstr_ParseResult = new string[] { "", ex.InnerException.Message, "AmadeusSendQueryV2" + "Level1" };
                        return rstr_ParseResult;
                    }
                    rstr_ParseResult = new string[] { "", ex.ToString(), "AmadeusSendQueryV2" + "Level2" };
                    return rstr_ParseResult;
                }
                strmRequestStream.Write(queryByte, 0, queryByte.Length);
                HttpWebResponse webResponse = null;
                try
                {
                    webResponse = (HttpWebResponse)webRequest.GetResponse();
                }
                catch (Exception e)
                {
                    FieldInfo fieldInformation = webRequest.GetType().GetField("_HttpResponse", BindingFlags.NonPublic | BindingFlags.Instance);
                    if (fieldInformation != null)
                    {
                        webResponse = (HttpWebResponse)fieldInformation.GetValue(webRequest);
                    }
                    if (webResponse == null)
                    {
                        strmRequestStream.Close();
                        if (e.InnerException != null)
                        {
                            rstr_ParseResult = new string[] { "", e.ToString(), "AmadeusSendQueryV2" + "Level3" };
                            return rstr_ParseResult;
                        }
                        rstr_ParseResult = new string[] { "", e.ToString(), "AmadeusSendQueryV2" + "Level4" };
                        return rstr_ParseResult;
                    }
                }

                Stream strmResponseStream = strmResponseStream = webResponse.GetResponseStream();
                if (webResponse.ContentEncoding.ToLower().Contains("gzip"))
                {
                    strmResponseStream = new GZipStream(strmResponseStream, CompressionMode.Decompress);
                }
                else if (webResponse.ContentEncoding.ToLower().Contains("deflate"))
                {
                    strmResponseStream = new DeflateStream(strmResponseStream, CompressionMode.Decompress);
                }
                StreamReader strmReader = new StreamReader(strmResponseStream, Encoding.Default);

                string strParseResult = strmReader.ReadToEnd();
                rstr_ParseResult = new string[] { strParseResult, "", "AmadeusSendQueryV2" + "Level0" };

                strmReader.Close();
                strmRequestStream.Close();
                strmResponseStream.Close();
                return rstr_ParseResult;
            }
            catch (Exception ex)
            {
                rstr_ParseResult = new string[] { "", ex.ToString(), "AmadeusSendQueryV2" + "Level-1" };
                return rstr_ParseResult;
            }
        }



        #endregion

        #region AirArabia
        [WebMethod(Description = "Send Request For Airarabia")]
        public string[] SendHttpwebrequestForG9Post(string pstrAgentId, string pstrTerminalId, string pstrTrackId,
                                                    string pstrCookie, string pstrRequestURL, string pstrRequestXml,
                                                    int pstrTimeOut)
        {

            string[] rstr_ParseResult = new string[4];
            try
            {
                string strWebCookie = "";
                HttpWebRequest httpwebRequest = (HttpWebRequest)HttpWebRequest.Create(pstrRequestURL);
                httpwebRequest.Credentials = CredentialCache.DefaultNetworkCredentials;

                httpwebRequest.Proxy = null;
                httpwebRequest.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
                httpwebRequest.Method = "POST";
                httpwebRequest.ContentType = "text/xml; charset=utf-8";
                httpwebRequest.Headers.Add("SOAPAction", "http://tempuri.org/");
                if (pstrTimeOut != -1)
                {
                    httpwebRequest.Timeout = pstrTimeOut;
                }


                if (!string.IsNullOrEmpty(pstrCookie))
                    httpwebRequest.Headers["Cookie"] = pstrCookie.TrimEnd(';');



                byte[] queryByte = Convertbyte(pstrRequestXml, Encoding.UTF8.GetEncoder());
                httpwebRequest.ContentLength = queryByte.Length;

                #region Write Request
                Stream strmRequestStream;
                try
                {
                    strmRequestStream = httpwebRequest.GetRequestStream();
                }
                catch (Exception ex)
                {
                    if (ex.InnerException != null)
                    {
                        rstr_ParseResult = new string[] { "", ex.InnerException.Message, "SendHttpwebrequestForG9Post" + "Level1", "" };
                        return rstr_ParseResult;
                    }
                    rstr_ParseResult = new string[] { "", ex.ToString(), "SendHttpwebrequestForG9Post" + "Level2", "" };
                    return rstr_ParseResult;
                }
                strmRequestStream.Write(queryByte, 0, queryByte.Length);
                #endregion

                HttpWebResponse webResponse = null;
                try
                {
                    webResponse = (HttpWebResponse)httpwebRequest.GetResponse();
                }
                catch (Exception e)
                {
                    FieldInfo fieldInformation = httpwebRequest.GetType().GetField("_HttpResponse", BindingFlags.NonPublic | BindingFlags.Instance);
                    if (fieldInformation != null)
                    {
                        webResponse = (HttpWebResponse)fieldInformation.GetValue(httpwebRequest);
                    }
                    if (webResponse == null)
                    {
                        strmRequestStream.Close();
                        if (e.InnerException != null)
                        {
                            rstr_ParseResult = new string[] { "", e.InnerException.ToString(), "SendHttpwebrequestForG9Post" + "Level3", "" };
                            return rstr_ParseResult;
                        }
                        rstr_ParseResult = new string[] { "", e.ToString(), "SendHttpwebrequestForG9Post" + "Level4", "" };
                        return rstr_ParseResult;
                    }
                }

                /// For G9 Cookies
                if (webResponse.Headers[HttpResponseHeader.SetCookie] != null)
                {
                    for (int i = 0; i < webResponse.Headers.Count; i++)
                    {
                        if (webResponse.Headers.GetKey(i).Contains("Set-Cookie"))
                        {
                            strWebCookie += webResponse.Headers[i].ToString();
                        }
                    }
                }

                Stream strmResponseStream = strmResponseStream = webResponse.GetResponseStream();
                if (webResponse.ContentEncoding.ToLower().Contains("gzip"))
                {
                    strmResponseStream = new GZipStream(strmResponseStream, CompressionMode.Decompress);
                }
                else if (webResponse.ContentEncoding.ToLower().Contains("deflate"))
                {
                    strmResponseStream = new DeflateStream(strmResponseStream, CompressionMode.Decompress);
                }
                StreamReader strmReader = new StreamReader(strmResponseStream, Encoding.Default);
                string strReturn = strmReader.ReadToEnd();
                strmReader.Close();
                strmRequestStream.Close();
                strmResponseStream.Close();
                rstr_ParseResult = new string[] { strReturn, "", "SendHttpwebrequestForG9Post" + "Level0", strWebCookie };
                return rstr_ParseResult;
            }
            catch (Exception ex)
            {
                rstr_ParseResult = new string[] { "", ex.ToString(), "SendHttpwebrequestForG9Post" + "Level-1", "" };
                return rstr_ParseResult;
            }
        }
        #endregion

        #region SendRequest For All
        [WebMethod(Description = "Send Request For Spice,Indigo,Airasia,Tiger,AirPeagasus,Flydubai,Aircosta,Air India Express")]
        public string[] SendRequestForRadixxNavitare(string pstrAgentId, string pstrTerminalId, string pstrTrackId,
                                                 string pstrCRSID, string pstrReqURL, string pstrReqSoapAction,
                                                 string pstrRequest, int pstrSetTimeOut)
        {
            //ref string strResponse, ref string strErrorReturn
            string[] rstr_ParseResult = new string[4];
            try
            {
                HttpWebRequest httpwebRequest = (HttpWebRequest)HttpWebRequest.Create(pstrReqURL);
                httpwebRequest.Credentials = CredentialCache.DefaultNetworkCredentials;
                httpwebRequest.Proxy = null;
                httpwebRequest.KeepAlive = true;
                httpwebRequest.ProtocolVersion = HttpVersion.Version11;
                httpwebRequest.ServicePoint.ConnectionLimit = 1;

                httpwebRequest.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
                httpwebRequest.Method = "POST";
                httpwebRequest.ContentType = "text/xml; charset=utf-8";
                httpwebRequest.Headers.Add("SOAPAction", pstrReqSoapAction);
                httpwebRequest.Accept = "text/xml";
                if (pstrSetTimeOut == -1)
                {
                    httpwebRequest.Timeout = pstrSetTimeOut;
                }
                byte[] queryByte = Convertbyte(pstrRequest, Encoding.UTF8.GetEncoder());
                httpwebRequest.ContentLength = queryByte.Length;

                #region Write Request
                Stream strmRequestStream;
                try
                {
                    strmRequestStream = httpwebRequest.GetRequestStream();
                }
                catch (Exception ex)
                {
                    if (ex.InnerException != null)
                    {
                        rstr_ParseResult = new string[] { "", ex.InnerException.Message, "SendRequestForRadixxNavitare" + "Level1", "" };
                        return rstr_ParseResult;
                    }
                    rstr_ParseResult = new string[] { "", ex.ToString(), "SendRequestForRadixxNavitare" + "Level2", "" };
                    return rstr_ParseResult;
                }
                strmRequestStream.Write(queryByte, 0, queryByte.Length);
                #endregion

                HttpWebResponse webResponse = null;
                try
                {
                    webResponse = (HttpWebResponse)httpwebRequest.GetResponse();
                }
                catch (Exception e)
                {
                    FieldInfo fieldInformation = httpwebRequest.GetType().GetField("_HttpResponse", BindingFlags.NonPublic | BindingFlags.Instance);
                    if (fieldInformation != null)
                    {
                        webResponse = (HttpWebResponse)fieldInformation.GetValue(httpwebRequest);
                    }
                    if (webResponse == null)
                    {
                        strmRequestStream.Close();
                        if (e.InnerException != null)
                        {
                            rstr_ParseResult = new string[] { "", e.InnerException.Message, "SendRequestForRadixxNavitare" + "Level3", "" };
                            return rstr_ParseResult;
                        }
                        rstr_ParseResult = new string[] { "", e.InnerException.Message, "SendRequestForRadixxNavitare" + "Level4", "" };
                        return rstr_ParseResult;
                    }
                }

                Stream strmResponseStream = strmResponseStream = webResponse.GetResponseStream();
                if (webResponse.ContentEncoding.ToLower().Contains("gzip"))
                {
                    strmResponseStream = new GZipStream(strmResponseStream, CompressionMode.Decompress);
                }
                else if (webResponse.ContentEncoding.ToLower().Contains("deflate"))
                {
                    strmResponseStream = new DeflateStream(strmResponseStream, CompressionMode.Decompress);
                }
                StreamReader strmReader = new StreamReader(strmResponseStream, Encoding.Default);
                string strResponse = strmReader.ReadToEnd();
                strmReader.Close();
                strmRequestStream.Close();
                strmResponseStream.Close();
                rstr_ParseResult = new string[] { strResponse, "", "SendRequestForRadixxNavitare" + "Level0", "" };
                return rstr_ParseResult;
            }
            catch (Exception ex)
            {
                rstr_ParseResult = new string[] { "", ex.ToString(), "SendRequestForRadixxNavitare" + "Level-1", "" };
                return rstr_ParseResult;
            }
        }


        public string[] Send_for_spiceseat(string pstrAgentId, string pstrTerminalId, string pstrTrackId,
                                                 string pstrCRSID, string pstrReqURL, string pstrReqSoapAction,
                                                 string pstrRequest, int pstrSetTimeOut)
        {
            string[] rstr_ParseResult = new string[4];
            try
            {


                HttpWebRequest httpwebRequest = (HttpWebRequest)HttpWebRequest.Create(pstrReqURL);
                httpwebRequest.Credentials = CredentialCache.DefaultNetworkCredentials;
                httpwebRequest.Proxy = null;
                httpwebRequest.KeepAlive = false;
                httpwebRequest.ProtocolVersion = HttpVersion.Version10;
                httpwebRequest.ServicePoint.ConnectionLimit = 1;
                httpwebRequest.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
                //ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
                httpwebRequest.Method = "POST";
                httpwebRequest.ContentType = "text/xml; charset=utf-8";
                httpwebRequest.Headers.Add("SOAPAction", pstrReqSoapAction);
                httpwebRequest.Accept = "text/xml";
                byte[] queryByte = Convertbyte(pstrRequest, Encoding.UTF8.GetEncoder());
                byte[] strbyte = System.Text.Encoding.UTF8.GetBytes(pstrRequest);
                httpwebRequest.ContentLength = queryByte.Length;

                #region Write Request
                Stream strmRequestStream;
                try
                {
                    strmRequestStream = httpwebRequest.GetRequestStream();
                }
                catch (Exception ex)
                {
                    if (ex.InnerException != null)
                    {
                        rstr_ParseResult = new string[] { "", ex.InnerException.Message, "SendRequestForRadixxNavitare" + "Level1", "" };
                        return rstr_ParseResult;
                    }
                    rstr_ParseResult = new string[] { "", ex.Message, "SendRequestForRadixxNavitare" + "Level1", "" };
                    return rstr_ParseResult;
                    //strError = ex.InnerException.Message;
                    //return false;
                }
                strmRequestStream.Write(queryByte, 0, queryByte.Length);
                #endregion

                HttpWebResponse webResponse = null;
                try
                {
                    webResponse = (HttpWebResponse)httpwebRequest.GetResponse();
                }
                catch (Exception e)
                {
                    FieldInfo fieldInformation = httpwebRequest.GetType().GetField("_HttpResponse", BindingFlags.NonPublic | BindingFlags.Instance);
                    if (fieldInformation != null)
                    {
                        webResponse = (HttpWebResponse)fieldInformation.GetValue(httpwebRequest);
                    }
                    if (webResponse == null)
                    {
                        strmRequestStream.Close();
                        if (e.InnerException != null)
                        {
                            rstr_ParseResult = new string[] { "", e.InnerException.Message, "SendRequestForRadixxNavitare" + "Level1", "" };
                            return rstr_ParseResult;
                        }
                        rstr_ParseResult = new string[] { "", e.Message, "SendRequestForRadixxNavitare" + "Level1", "" };
                        return rstr_ParseResult;
                    }
                }
                Stream strmResponseStream = strmResponseStream = webResponse.GetResponseStream();
                if (webResponse.ContentEncoding.ToLower().Contains("gzip"))
                {
                    strmResponseStream = new GZipStream(strmResponseStream, CompressionMode.Decompress);
                }
                else if (webResponse.ContentEncoding.ToLower().Contains("deflate"))
                {
                    strmResponseStream = new DeflateStream(strmResponseStream, CompressionMode.Decompress);
                }
                StreamReader strmReader = new StreamReader(strmResponseStream, Encoding.Default);
                string strResponse = strmReader.ReadToEnd();
                strmReader.Close();
                strmRequestStream.Close();
                strmResponseStream.Close();
                rstr_ParseResult = new string[] { strResponse, "", "", "" };
                return rstr_ParseResult;
            }
            catch (Exception ex)
            {

                rstr_ParseResult = new string[] { "", ex.ToString(), "SendRequestForRadixxNavitare" + "Level-1", "" };
                return rstr_ParseResult;
            }
        }
        #endregion

        #region SendRequest for SpiceMoney
        [WebMethod(Description = "Send Request For Spice Money Transfer")]
        public bool SendRequestForSpiceMoneyTransfer(string AgentId, string TerminalId, string SequenceId, string CRSID, string URL, string Method, string Token, string JsonRequest, int intTimeout, ref string strhtmlResponse, ref string Error)
        {
            try
            {
                HttpWebRequest request = (HttpWebRequest)HttpWebRequest.Create(URL);
                request.Method = Method;
                request.Accept = "application/json";
                request.ContentType = "application/json";
                request.Timeout = intTimeout;
                ServicePointManager.ServerCertificateValidationCallback += new RemoteCertificateValidationCallback(ValidateRemoteCertificate);
                string authInfo = Convert.ToBase64String(System.Text.Encoding.Default.GetBytes(Token));
                request.Headers["Authorization"] = "Basic " + authInfo;
                request.Headers["srid"] = "fb";
                using (StreamWriter swt = new StreamWriter(request.GetRequestStream()))
                {
                    swt.Write(JsonRequest);
                }
                WebResponse webResponse = (HttpWebResponse)request.GetResponse();
                Stream responsestream = webResponse.GetResponseStream();
                StreamReader srResponse;
                using (srResponse = new StreamReader(responsestream))
                {
                    strhtmlResponse = srResponse.ReadToEnd();
                    // Close and clean up the StreamReader
                    srResponse.Close();
                    if (string.IsNullOrEmpty(strhtmlResponse))
                        return false;
                }
            }
            catch (Exception ex)
            {
                Error = ex.ToString();
                return false;
            }
            return true;
        }
        #endregion

        #region SendRequest for CyberPlat
        //[WebMethod(Description = "Send Request For CyberPlat")]
        //public bool SendRequestForCyberPlat(string AgentId, string TerminalId, string SequenceId, string URL, string Method, string CertName, string Password, string Request, ref string Response, ref string Error)
        //{
        //    try
        //    {
        //        OpenSSL _OpenSSL = new OpenSSL();
        //        string CERTPATH = ConfigurationManager.AppSettings["CERTPATH"].ToString();
        //        CERTPATH = CERTPATH + CertName;
        //        _OpenSSL.message = _OpenSSL.Sign_With_PFX(Request, CERTPATH, Password);
        //        _OpenSSL.htmlText = _OpenSSL.CallCryptoAPI(_OpenSSL.message, URL);
        //        string Temp = _OpenSSL.htmlText;
        //        if (string.IsNullOrEmpty(_OpenSSL.htmlText))
        //        {
        //            Error = "IP:Unable to connect remote server.";
        //            return false;
        //        }
        //        Response = _OpenSSL.htmlText;
        //        return true;
        //    }
        //    catch (Exception ex)
        //    {
        //        Error = ex.ToString();
        //        return false;
        //    }
        //}
        #endregion


        #region For 2T
        [WebMethod(Description = "Send Request For Trujet")]
        public string[] SendRequestForTrujet(string pstrAgentId, string pstrTerminalId, string pstrTrackId,
                                    string pstrCookie, string pstrRequestURL, string pstrRequestXml,
                                    string pstrMethod, int pstrTimeOut)
        {

            //ref Hashtable hshTable, string CRSID, ref string Error
            string[] rstr_ParseResult = new string[4];
            try
            {
                string rstrResponse = string.Empty;
                string rstrCookie = string.Empty;

                MyWebClient webclient = new MyWebClient();
                byte[] bytResponse = new byte[] { };
                string strCookieValue = string.Empty;
                webclient.Headers.Add("Content-Type", "application/x-www-form-urlencoded");
                webclient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.2; WOW64; rv:35.0) Gecko/20100101 Firefox/35.0");
                webclient.Headers.Add("Accept-Encoding", "gzip, deflate");
                webclient.Headers.Add("Cache-Control", "no-cache");
                string strCookie = pstrCookie;

                if (!string.IsNullOrEmpty(strCookie))
                {
                    webclient.Headers["Cookie"] = strCookie.TrimEnd(';');
                }
                if (pstrMethod.Contains("GET"))
                {
                    bytResponse = webclient.DownloadData(pstrRequestURL);
                    rstrResponse = Encoding.ASCII.GetString(bytResponse);
                }
                else if (pstrMethod.Contains("POST"))
                {
                    bytResponse = webclient.UploadData(pstrRequestURL, "POST", Encoding.ASCII.GetBytes(pstrRequestXml));
                    rstrResponse = Encoding.ASCII.GetString(bytResponse);
                }
                for (int i = 0; i < webclient.ResponseHeaders.Count; i++)
                {
                    if (webclient.ResponseHeaders.AllKeys[i].ToString().Contains("Set-Cookie"))
                    {
                        if (!string.IsNullOrEmpty(webclient.ResponseHeaders[HttpResponseHeader.SetCookie].ToString()))
                        {
                            strCookieValue = webclient.ResponseHeaders[HttpResponseHeader.SetCookie].ToString();
                            break;
                        }
                    }
                }
                rstrCookie = strCookieValue;

                rstr_ParseResult = new string[] { rstrResponse, "", "SendRequestForTrujet" + "Level0", rstrCookie };
                return rstr_ParseResult;
            }
            catch (Exception ex)
            {
                rstr_ParseResult = new string[] { "", ex.Message, "SendRequestForTrujet" + "Level-1", "" };
                return rstr_ParseResult;
            }
        }

        [WebMethod(Description = "Send Request For Trujet with Referer")]
        public string[] SendRequestForTrujetwithReferer(string pstrAgentId, string pstrTerminalId, string pstrTrackId,
                                    string pstrCookie, string pstrRequestURL, string pstrRequestXml,
                                    string pstrReferer, string pstrMethod, int pstrTimeOut)
        {
            string rpstrResponse = string.Empty;
            string[] rstr_ParseResult = new string[4];
            try
            {
                DateTime dtnow = DateTime.Now;
                MyWebClient webclient = new MyWebClient();
                byte[] bytResponse = new byte[] { };
                string strCookieValue = string.Empty;
                webclient.Headers.Add("Content-Type", "application/x-www-form-urlencoded");
                webclient.Headers.Add("Referer", pstrReferer);
                webclient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.2; WOW64; rv:37.0) Gecko/20100101 Firefox/37.0");
                webclient.Headers.Add("Accept-Encoding", "gzip, deflate");
                webclient.Headers.Add("Cache-Control", "no-cache");
                string strCookie = pstrCookie;
                if (!string.IsNullOrEmpty(strCookie))
                {
                    webclient.Headers["Cookie"] = strCookie.TrimEnd(';');
                }
                if (pstrMethod.Contains("GET"))
                {
                    bytResponse = webclient.DownloadData(pstrRequestURL);
                    rpstrResponse = Encoding.ASCII.GetString(bytResponse);
                }
                if (pstrMethod.Contains("POST"))
                {
                    bytResponse = webclient.UploadData(pstrRequestURL, "POST", Encoding.ASCII.GetBytes(pstrRequestXml));
                    rpstrResponse = Encoding.ASCII.GetString(bytResponse);
                }

                for (int i = 0; i < webclient.ResponseHeaders.Count; i++)
                {
                    if (webclient.ResponseHeaders.AllKeys[i].ToString().Contains("Set-Cookie"))
                    {
                        if (!string.IsNullOrEmpty(webclient.ResponseHeaders[HttpResponseHeader.SetCookie].ToString()))
                        {
                            strCookieValue = webclient.ResponseHeaders[HttpResponseHeader.SetCookie].ToString();
                            break;
                        }
                    }
                }
                rstr_ParseResult = new string[] { rpstrResponse, "", "SendRequestForTrujetwithReferer" + "Level0", "" };
                return rstr_ParseResult;
            }
            catch (Exception ex)
            {
                rstr_ParseResult = new string[] { "", ex.ToString(), "SendRequestForTrujetwithReferer" + "Level-1", "" };
                return rstr_ParseResult;
            }
        }

        [WebMethod(Description = "Etravel Bus")]
        public string[] SendRequestForETSwithBasicAuthe(string pstrAgentId, string pstrTerminalId, string pstrTrackId,
                                   string pstrUserName, string pstrPassword, string pstrRequestURL, string pstrRequestXml,
                                    string pstrMethod, int pstrTimeOut)
        {
            string[] rstr_ParseResult = new string[4];
            try
            {
                WebClient wcRQ = new WebClient();
                byte[] bytarrRequest = new byte[] { };
                byte[] bytarrResponse = new byte[] { };
                wcRQ.Credentials = new NetworkCredential(pstrUserName, pstrPassword);
                wcRQ.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
                wcRQ.Headers.Add("content-type", "application/json");
                wcRQ.Headers.Add("Timeout", "60000");
                string strSoapAction = "";
                if (!string.IsNullOrEmpty(strSoapAction))
                    wcRQ.Headers.Add("SOAPAction", strSoapAction);
                if (pstrMethod.ToUpper().Equals("GET"))
                {
                    bytarrResponse = wcRQ.DownloadData(pstrRequestURL);
                }
                else if (pstrMethod.ToUpper().Equals("POST"))
                {
                    bytarrRequest = Encoding.ASCII.GetBytes(pstrRequestXml);
                    bytarrResponse = wcRQ.UploadData(pstrRequestURL, bytarrRequest);
                }

                string strResponse = Encoding.ASCII.GetString(bytarrResponse);
                rstr_ParseResult = new string[] { strResponse, "", "SendRequestForETSwithBasicAuthe" + "Level-1", "" };
            }
            catch (Exception ex)
            {
                string strError = ex.Message.ToString();
                rstr_ParseResult = new string[] { "", ex.Message, "SendRequestForETSwithBasicAuthe" + "Level-2", "" };
            }
            return rstr_ParseResult;
        }
        #endregion

        #region Grn
        [WebMethod(Description = "Send Request For Grn with Referer")]
        public string[] PostOnWebGrn(string TerminalId, string Seq, string URL, string strXMLData, ref string strResponse, ref string strError)
        {
            string[] rstr_ParseResult = new string[4];
            try
            {

                string strPostData = strXMLData;
                System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
                byte[] byte1 = encoding.GetBytes(strPostData);

                System.Net.HttpWebRequest HttpWReq = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(URL);
                HttpWReq.ContentType = "text/xml";
                HttpWReq.ContentLength = byte1.Length;

                HttpWReq.Timeout = 600000;
                HttpWReq.Headers["Accept-Encoding"] = "gzip, deflate";

                HttpWReq.Method = "POST";

                System.IO.Stream StreamData = HttpWReq.GetRequestStream();

                StreamData.Write(byte1, 0, byte1.Length);
                StreamData.Close();

                System.Net.HttpWebResponse WebResponse = (HttpWebResponse)HttpWReq.GetResponse();
                if ((WebResponse.StatusCode == System.Net.HttpStatusCode.OK))
                {
                    System.IO.Stream responseStream = null;

                    if ((WebResponse.Headers.Get("Content-Encoding") == "gzip"))
                    {
                        responseStream = WebResponse.GetResponseStream();

                        //responseStream = new GZipStream(responseStream, CompressionMode.Decompress);
                        responseStream = new System.IO.Compression.GZipStream(responseStream, System.IO.Compression.CompressionMode.Decompress);
                    }
                    else
                    {
                        responseStream = WebResponse.GetResponseStream();
                    }
                    System.IO.StreamReader reader = new System.IO.StreamReader(responseStream);
                    strResponse = reader.ReadToEnd();
                    WebResponse.Close();
                    //return strResponse;
                }
                else
                {

                    WebResponse.Close();

                    if ((WebResponse.ContentType == "text/xml;charset=UTF-8"))
                    {
                        //** Error XML returned, so process the error
                    }
                    else
                    {
                        //**  Other error
                    }
                    rstr_ParseResult = new string[] { "", "Status Error" + WebResponse.StatusCode, "PostOnWebGrn" + "Level-1", "" };
                    return rstr_ParseResult;
                }

                WebResponse.Close();
                rstr_ParseResult = new string[] { strResponse, "", "PostOnWebGrn" + "Level-1", "" };
                return rstr_ParseResult;
            }
            catch (Exception ex)
            {

                rstr_ParseResult = new string[] { "", ex.ToString(), "PostOnWebGrn" + "Level-1", "" };
                return rstr_ParseResult;
            }
        }

        [WebMethod(Description = "Send Request For Grn with Referer")]
        public string[] PostOnWebGrnConnect(string TerminalId, string Seq, string URL, string strXMLData)
        {
            string[] rstr_ParseResult = new string[4];
            try
            {
                string strResponse = "";

                string strPostData = strXMLData;
                System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
                byte[] byte1 = encoding.GetBytes(strPostData);

                System.Net.HttpWebRequest HttpWReq = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(URL);
                HttpWReq.ContentType = "text/xml";
                HttpWReq.ContentLength = byte1.Length;

                HttpWReq.Timeout = 600000;
                HttpWReq.Headers["Accept-Encoding"] = "gzip, deflate";

                HttpWReq.Method = "POST";

                System.IO.Stream StreamData = HttpWReq.GetRequestStream();

                StreamData.Write(byte1, 0, byte1.Length);
                StreamData.Close();

                System.Net.HttpWebResponse WebResponse = (HttpWebResponse)HttpWReq.GetResponse();
                if ((WebResponse.StatusCode == System.Net.HttpStatusCode.OK))
                {
                    System.IO.Stream responseStream = null;

                    if ((WebResponse.Headers.Get("Content-Encoding") == "gzip"))
                    {
                        responseStream = WebResponse.GetResponseStream();

                        //responseStream = new GZipStream(responseStream, CompressionMode.Decompress);
                        responseStream = new System.IO.Compression.GZipStream(responseStream, System.IO.Compression.CompressionMode.Decompress);
                    }
                    else
                    {
                        responseStream = WebResponse.GetResponseStream();
                    }
                    System.IO.StreamReader reader = new System.IO.StreamReader(responseStream);
                    strResponse = reader.ReadToEnd();
                    WebResponse.Close();
                    //return strResponse;
                }
                else
                {

                    WebResponse.Close();

                    if ((WebResponse.ContentType == "text/xml;charset=UTF-8"))
                    {
                        //** Error XML returned, so process the error
                    }
                    else
                    {
                        //**  Other error
                    }
                    rstr_ParseResult = new string[] { "", "Status Error" + WebResponse.StatusCode, "PostOnWebGrn" + "Level-1", "" };
                    return rstr_ParseResult;
                }

                WebResponse.Close();
                rstr_ParseResult = new string[] { strResponse, "", "PostOnWebGrn" + "Level-1", "" };
                return rstr_ParseResult;
            }
            catch (Exception ex)
            {

                rstr_ParseResult = new string[] { "", ex.ToString(), "PostOnWebGrn" + "Level-1", "" };
                return rstr_ParseResult;
            }
        }
        #endregion

        #region LotsOfHotel
        [WebMethod(Description = "Send Request For LOH with Referer")]
        public string[] SendRequestLOH(string strURL, string strMethod, string strSoapAction, string strRequestData, ref string strWebResponse, ref string strWebError)
        {
            string[] rstr_ParseResult = new string[4];
            try
            {
                if (string.IsNullOrEmpty(strURL))
                {
                    strWebError = "Url is Empty";
                    return rstr_ParseResult;
                }

                HttpWebRequest HttpReq = (HttpWebRequest)WebRequest.Create(strURL);
                HttpReq.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
                HttpReq.Headers.Add(HttpRequestHeader.AcceptLanguage, "en-us,en;q=0.5");
                HttpReq.UserAgent = "Mozilla/5.0 (Windows NT 5.1; rv:18.0) Gecko/20100101 Firefox/18.0";
                HttpReq.Accept = "application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
                HttpReq.ContentType = "text/xml; charset=utf-8";
                if (!string.IsNullOrEmpty(strSoapAction))
                    HttpReq.Headers.Add("SoapAction", strSoapAction);
                HttpReq.Timeout = 120 * 1000;

                if (strMethod.ToUpper().Equals("GET"))
                {
                    HttpReq.Method = "GET";
                }
                else if (strMethod.ToUpper().Equals("POST"))
                {
                    HttpReq.Method = "POST";
                    byte[] lbPostBuffer = Encoding.Default.GetBytes(strRequestData);
                    HttpReq.ContentLength = lbPostBuffer.Length;

                    Stream PostStream = HttpReq.GetRequestStream();
                    PostStream.Write(lbPostBuffer, 0, lbPostBuffer.Length);
                    PostStream.Close();
                }
                else if (strMethod.ToUpper().Equals("DELETE"))
                {
                    HttpReq.Method = "DELETE";
                }

                HttpWebResponse WebResponse = null;
                try
                {
                    WebResponse = (HttpWebResponse)HttpReq.GetResponse();
                }
                catch (Exception e)
                {
                    FieldInfo fieldInformation = HttpReq.GetType().GetField("_HttpResponse", BindingFlags.NonPublic | BindingFlags.Instance);
                    if (fieldInformation != null)
                    {
                        WebResponse = (HttpWebResponse)fieldInformation.GetValue(HttpReq);
                    }
                    if (WebResponse == null)
                    {
                        if (e.InnerException != null)
                        {
                            strWebResponse = e.InnerException.Message;
                            return rstr_ParseResult;
                        }
                        strWebResponse = e.Message;
                        return rstr_ParseResult;
                    }
                }

                Stream rsStream = WebResponse.GetResponseStream();
                if (WebResponse.ContentEncoding.ToLower().Contains("gzip"))
                {
                    rsStream = new GZipStream(rsStream, CompressionMode.Decompress);
                }
                else if (WebResponse.ContentEncoding.ToLower().Contains("deflate"))
                {
                    rsStream = new DeflateStream(rsStream, CompressionMode.Decompress);
                }

                StreamReader Reader = new StreamReader(rsStream, Encoding.Default);
                strWebResponse = Reader.ReadToEnd();
                WebResponse.Close();
                rstr_ParseResult = new string[] { strWebResponse, "", "", "" };
                rsStream.Close();
                return rstr_ParseResult;
            }
            catch (Exception ex)
            {
                string strLineNo = string.Empty;
                if (ex.StackTrace != null)
                {
                    if (ex.StackTrace.Contains("cs:line"))
                    {
                        strLineNo = ex.StackTrace.Substring(ex.StackTrace.IndexOf("cs:line"));
                    }
                }
                string strException = "<Exception>" + ex.Message.ToString() + "</Exception>";
                //_clsCommon.WriteEventLog(strTerminalID, strSequenceNo, strException, "RQ", "Exception", "SendHttpWebRequest", "FAILED", "SendRequest");
                strWebError = strException;
                return rstr_ParseResult = new string[] { strWebResponse, strWebError, "", "" };
            }
        }

        #endregion

        #region Scraping Areas
        [WebMethod(Description = "ETS POST")]
        public string[] ETSInvokePostRequest(string requestUrl, string requestBody, string userName, string password, int TimeOut)
        //ref string strResponseData, ref string strError)
        {
            string[] str_Return = new string[4];
            string completeUrl = requestUrl;
            string strResponseData = "";
            string strError = "";
            try
            {
                HttpWebRequest httpRequest = WebRequest.Create(completeUrl) as HttpWebRequest;
                httpRequest.Credentials = new NetworkCredential(userName, password);
                httpRequest.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
                httpRequest.ContentType = @"application/json";
                httpRequest.Method = @"POST";
                httpRequest.Timeout = TimeOut;

                StreamWriter requestWriter = new StreamWriter(httpRequest.GetRequestStream());
                requestWriter.Write(requestBody);
                requestWriter.Close();
                HttpWebResponse httpResponse = (HttpWebResponse)httpRequest.GetResponse();
                StreamReader responseReader = new StreamReader(httpResponse.GetResponseStream());
                strResponseData = responseReader.ReadToEnd();
                return str_Return = new string[] { strResponseData, "", "", "" };
            }
            catch (WebException ex)
            {
                if (ex.Response == null)
                {
                    strError = "(Server)" + ex.Message.ToString();
                    return str_Return = new string[] { strResponseData, strError, "", "" };
                }
                using (var reader = new StreamReader(ex.Response.GetResponseStream()))
                {
                    strError = reader.ReadToEnd();
                    return str_Return = new string[] { strResponseData, strError, "", "" };
                }
            }
            catch (Exception ex)
            {
                strError = "(Server)" + ex.Message.ToString();
                return str_Return = new string[] { strResponseData, strError, "", "" };
            }
        }




        [WebMethod(Description = "ETS Get")]
        public string[] ETSInvokeGetRequest(string requestUrl, string userName, string password, int TimeOut)
        //ref string strResponseData, ref string strError)
        {
            string[] str_Return = new string[4];
            string completeUrl = requestUrl;
            string strResponseData = "";
            string strError = "";
            try
            {
                HttpWebRequest httpRequest = WebRequest.Create(completeUrl) as HttpWebRequest;
                httpRequest.Credentials = new NetworkCredential(userName, password);
                httpRequest.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
                httpRequest.ContentType = @"application/json";
                httpRequest.Method = @"GET";
                httpRequest.Timeout = TimeOut;

                HttpWebResponse httpResponse = (HttpWebResponse)httpRequest.GetResponse();
                //httpResponse.ContentType = "application/zip";
                //StreamReader reader = new StreamReader(httpResponse.GetResponseStream());
                //Stream strmResponse = httpResponse.GetResponseStream();
                //if (httpResponse.ContentEncoding.ToLower().Contains("gzip"))
                //{
                //    strmResponse = new GZipStream(strmResponse, CompressionMode.Decompress);
                //}
                //if (httpResponse.ContentEncoding.ToLower().Contains("deflate"))
                //{
                //    strmResponse = new DeflateStream(strmResponse, CompressionMode.Decompress);
                //}
                StreamReader strmReader = new StreamReader(httpResponse.GetResponseStream());
                strResponseData = strmReader.ReadToEnd();
                return str_Return = new string[] { strResponseData, strError, "", "" };
            }
            catch (WebException ex)
            {
                if (ex.Response == null)
                {
                    strError = ex.Message.ToString();
                    return str_Return = new string[] { strResponseData, strError, "", "" };
                }
                using (var reader = new StreamReader(ex.Response.GetResponseStream()))
                {
                    strError = reader.ReadToEnd();
                    return str_Return = new string[] { strResponseData, strError, "", "" };
                }
            }
            catch (Exception ex)
            {
                strError = "(Server)" + ex.Message.ToString();
                return str_Return = new string[] { strResponseData, strError, "", "" };
            }
        }


        #endregion

        #region SendRequest for Trujetifly
        [WebMethod(Description = "Send Request For Trujetifly New")]
        public bool SendRequestForTrujetifly(string strAgentId, string strTerminalId, string Password, string Username, string strSequenceNo, string strCRSID, string strReqURL, string strWebMethod, string strReqSoapAction, string strRequest, string strSetTimeOut, ref string strResponse, ref string strErrorReturn)
        {
            string strExceptionStatus = string.Empty;
            try
            {
                string strRequestURL = strReqURL;

                #region New Sendrequest

                HttpWebRequest httpwebRequest = (HttpWebRequest)HttpWebRequest.Create(strRequestURL);
                httpwebRequest.Credentials = CredentialCache.DefaultNetworkCredentials;
                httpwebRequest.Proxy = null;

                httpwebRequest.KeepAlive = true;
                System.Net.ServicePointManager.Expect100Continue = false;
                httpwebRequest.ProtocolVersion = HttpVersion.Version11;
                httpwebRequest.ServicePoint.ConnectionLimit = 1;

                // ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 || (SecurityProtocolType)192 | (SecurityProtocolType)768 | (SecurityProtocolType)372;
                ServicePointManager.SecurityProtocol = (SecurityProtocolType)192 | (SecurityProtocolType)768 | (SecurityProtocolType)3072 | SecurityProtocolType.Tls12 | SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls; ;
                httpwebRequest.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
                httpwebRequest.Method = "POST";
                httpwebRequest.ContentType = "text/xml; charset=utf-8";
                // httpwebRequest.Headers.Add("SOAPAction", "http://tempuri.org/");
                httpwebRequest.Headers.Add("Username", Username);
                httpwebRequest.Headers.Add("Password", Password);
                httpwebRequest.Timeout = 300000;
                string strCookie = string.Empty;
                //foreach (DictionaryEntry hshvalue in hshHeaders)
                //    strCookie += hshvalue.Key.ToString() + "=" + hshvalue.Value.ToString() + ";";

                if (!string.IsNullOrEmpty(strCookie))
                    httpwebRequest.Headers["Cookie"] = strCookie.TrimEnd(';');

                //string strRequestXml = strRequestXml;// GetSoapEnvelope(strRequestXml, hshCredential);
                byte[] queryByte = Convertbyte(strRequest, Encoding.UTF8.GetEncoder());
                httpwebRequest.ContentLength = queryByte.Length;

                #region Request
                Stream strmRequestStream;
                try
                {
                    strmRequestStream = httpwebRequest.GetRequestStream();
                }
                catch (Exception ex)
                {

                    if (ex.InnerException != null)
                    {
                        strErrorReturn = ex.InnerException.Message;
                        return false;
                    }
                    strErrorReturn = ex.InnerException.Message;
                    return false;
                }
                strmRequestStream.Write(queryByte, 0, queryByte.Length);
                #endregion

                HttpWebResponse webResponse = null;
                try
                {
                    webResponse = (HttpWebResponse)httpwebRequest.GetResponse();
                }
                catch (Exception e)
                {
                    FieldInfo fieldInformation = httpwebRequest.GetType().GetField("_HttpResponse", BindingFlags.NonPublic | BindingFlags.Instance);
                    if (fieldInformation != null)
                    {
                        webResponse = (HttpWebResponse)fieldInformation.GetValue(httpwebRequest);
                    }
                    if (webResponse == null)
                    {
                        strmRequestStream.Close();
                        if (e.InnerException != null)
                        {
                            strErrorReturn = e.InnerException.Message;
                            return false;
                        }
                        strErrorReturn = e.Message;
                        return false;
                    }
                }
                Stream strmResponseStream = strmResponseStream = webResponse.GetResponseStream();
                if (webResponse.ContentEncoding.ToLower().Contains("gzip"))
                {
                    strmResponseStream = new GZipStream(strmResponseStream, CompressionMode.Decompress);
                }
                else if (webResponse.ContentEncoding.ToLower().Contains("deflate"))
                {
                    strmResponseStream = new DeflateStream(strmResponseStream, CompressionMode.Decompress);
                }
                StreamReader strmReader = new StreamReader(strmResponseStream, Encoding.Default);
                strResponse = strmReader.ReadToEnd();
                strmReader.Close();
                strmRequestStream.Close();
                strmResponseStream.Close();
                #endregion

                return true;
            }
            catch (Exception ex)
            {
                strErrorReturn = ex.ToString();
                return false;
            }
            return true;
        }
        #endregion

        [WebMethod(Description = "24x7Rooms")]
        public bool SendHttpWebRequest24x7(string TerminalId, string Seq, string strMethod, string strURL, string strRequestData, ref string strWebResponse, ref string strWebError)
        {
            try
            {
                //if (ConfigurationManager.AppSettings["24x7Rooms"] != null && ConfigurationManager.AppSettings["24x7Rooms"].ToString() != "")
                //{
                //    IpHelpV2.PatchIPHelp _patchHelp = new IpHelpV2.PatchIPHelp();
                //    _patchHelp.Url = "http://" + ConfigurationManager.AppSettings["24x7Rooms"].ToString() + "/IP_HELP_V2.0/PatchIPHelp.asmx";
                //    int i = 0;
                //    string[] str_Response = _patchHelp.SendRequestForRadixxNavitare("", "", "", "", strURL, strMethod, strRequestData, 20);
                //    if (str_Response[0] != "")
                //    {
                //        strWebResponse = str_Response[0];
                //        return true;
                //    }
                //    else
                //    {
                //        strWebResponse = str_Response[1];
                //        return false;
                //    }
                //}

                if (string.IsNullOrEmpty(strURL))
                {
                    strWebError = "Url is Empty";
                    return false;
                }
                //  string strApiKey = "63ebc0b8e30d786ba0d1f608dd1f0006";
                HttpWebRequest HttpReq = (HttpWebRequest)WebRequest.Create(strURL);
                HttpReq.ContentType = "application/json";
                // HttpReq.Headers.Add("api-key", strApiKey);
                HttpReq.Headers.Add("cache-control", "no-cache");
                HttpReq.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
                HttpReq.Accept = "application/json";
                HttpReq.Timeout = 180 * 1000;
                if (strMethod.ToUpper().Equals("GET"))
                {
                    HttpReq.Method = "GET";
                }
                else if (strMethod.ToUpper().Equals("POST"))
                {
                    HttpReq.Method = "POST";
                    byte[] lbPostBuffer = Encoding.Default.GetBytes(strRequestData);
                    HttpReq.ContentLength = lbPostBuffer.Length;
                    Stream PostStream = HttpReq.GetRequestStream();
                    PostStream.Write(lbPostBuffer, 0, lbPostBuffer.Length);
                    PostStream.Close();
                }
                else if (strMethod.ToUpper().Equals("DELETE"))
                {
                    HttpReq.Method = "DELETE";
                    //byte[] lbPostBuffer = Encoding.Default.GetBytes(strRequestData);
                    //HttpReq.ContentLength = lbPostBuffer.Length;
                    //Stream PostStream = HttpReq.GetRequestStream();
                    //PostStream.Write(lbPostBuffer, 0, lbPostBuffer.Length);
                    //PostStream.Close();
                }
                HttpWebResponse WebResponse = null;
                try
                {
                    WebResponse = (HttpWebResponse)HttpReq.GetResponse();
                }
                catch (Exception e)
                {
                    FieldInfo fieldInformation = HttpReq.GetType().GetField("_HttpResponse", BindingFlags.NonPublic | BindingFlags.Instance);
                    if (fieldInformation != null)
                    {
                        WebResponse = (HttpWebResponse)fieldInformation.GetValue(HttpReq);
                    }
                    if (WebResponse == null)
                    {
                        if (e.InnerException != null)
                        {
                            strWebResponse = e.InnerException.Message;
                            return false;
                        }
                        strWebResponse = e.Message;
                        return false;
                    }
                }
                // HttpWebResponse WebResponse = (HttpWebResponse)HttpReq.GetResponse();
                Stream responseStream = responseStream = WebResponse.GetResponseStream();
                if (WebResponse.ContentEncoding.ToLower().Contains("gzip"))
                {
                    responseStream = new GZipStream(responseStream, CompressionMode.Decompress);
                }
                else if (WebResponse.ContentEncoding.ToLower().Contains("deflate"))
                {
                    responseStream = new DeflateStream(responseStream, CompressionMode.Decompress);
                }
                responseStream = new DeflateStream(responseStream, CompressionMode.Decompress);
                StreamReader Reader = new StreamReader(responseStream, Encoding.Default);
                strWebResponse = Reader.ReadToEnd();
                WebResponse.Close();
                responseStream.Close();
                return true;
            }
            catch (Exception ex)
            {
                string strLineNo = string.Empty;
                if (ex.StackTrace != null)
                {
                    if (ex.StackTrace.Contains("cs:line"))
                    {
                        strLineNo = ex.StackTrace.Substring(ex.StackTrace.IndexOf("cs:line"));
                    }
                }
                string strException = "<Exception>" + ex.Message.ToString() + "</Exception>";
                // _clsCommon.WriteEventLog(strTerminalID, strSequenceNo, strException, "RQ", "Exception", "SendHttpWebRequest", "FAILED", "SendRequest");
                strWebError = strException;
                return false;
            }
        }

        [WebMethod(Description = "IRCTC")]
        public string[] SendRequestIRCTC(string IRCTCURL, string CERTNAME, string RequestURL, string Parameters, string Method,
            string UserName, string Password, string pCookies)
        {
            string LogDetails = string.Empty;
            string[] str_Array = new string[5];
            string[] Cookies = new string[] { };
            string Response = "";
            string Error = "";
            try
            {
                string[] MainCookie = new string[] { };
                if (pCookies.Contains("JOIN-"))
                {
                    MainCookie = Regex.Split(pCookies, "JOIN-");
                }
                string CERTPATH = ConfigurationManager.AppSettings["CERTPATH"].ToString();
                HttpWebRequest httpwebRequest = (HttpWebRequest)HttpWebRequest.Create(RequestURL);
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
                httpwebRequest.Proxy = null;
                httpwebRequest.KeepAlive = false;
                httpwebRequest.ProtocolVersion = HttpVersion.Version11;
                httpwebRequest.ServicePoint.ConnectionLimit = 100;
                httpwebRequest.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
                httpwebRequest.Method = Method;
                httpwebRequest.ContentType = "application/xml";
                httpwebRequest.Accept = "application/xml";
                httpwebRequest.ClientCertificates.Add(new X509Certificate2(CERTPATH + CERTNAME, "123456", X509KeyStorageFlags.MachineKeySet));
                ServicePointManager.ServerCertificateValidationCallback += new RemoteCertificateValidationCallback(ValidateRemoteCertificate);
                NetworkCredential _ntwkCredential = new NetworkCredential(UserName, Password);
                CredentialCache _CacheCredential = new CredentialCache();
                _CacheCredential.Add(new Uri(IRCTCURL), "Basic", _ntwkCredential);
                httpwebRequest.Credentials = _ntwkCredential;
                if (MainCookie.Length > 0)
                {
                    httpwebRequest.Headers.Add((MainCookie[0].Split('='))[0], ((MainCookie[0].Split('='))[1]).Split(';')[0]);
                }

                if (Method.Equals("POST"))
                {
                    Stream strmInput = null;
                    byte[] bytarrParam = Convertbyte(Parameters, Encoding.UTF8.GetEncoder());
                    httpwebRequest.ContentLength = bytarrParam.Length;
                    strmInput = httpwebRequest.GetRequestStream();
                    strmInput.Write(bytarrParam, 0, bytarrParam.Length);
                }
                HttpWebResponse webResponse = null;
                try
                {
                    webResponse = (HttpWebResponse)httpwebRequest.GetResponse();
                }
                catch (Exception e)
                {
                    Error = "Error: " + e.Message;
                    FieldInfo fieldInformation = httpwebRequest.GetType().GetField("_HttpResponse", BindingFlags.NonPublic | BindingFlags.Instance);
                    if (fieldInformation != null)
                    {
                        webResponse = (HttpWebResponse)fieldInformation.GetValue(httpwebRequest);
                    }
                }
                Stream strmResponseStream = strmResponseStream = webResponse.GetResponseStream();
                if (webResponse.ContentEncoding.ToLower().Contains("gzip"))
                {
                    strmResponseStream = new GZipStream(strmResponseStream, CompressionMode.Decompress);
                }
                else if (webResponse.ContentEncoding.ToLower().Contains("deflate"))
                {
                    strmResponseStream = new DeflateStream(strmResponseStream, CompressionMode.Decompress);
                }

                for (int i = 0; i < webResponse.Headers.Count; i++)
                {
                    if (webResponse.Headers.GetKey(i).ToString() == "Set-Cookie")
                    {
                        Cookies = webResponse.Headers.GetValues(i);
                        MainCookie = Cookies;
                    }
                }
                StreamReader strmReader = new StreamReader(strmResponseStream, Encoding.Default);
                Response = strmReader.ReadToEnd();
                strmReader.Close();
                strmResponseStream.Close();

                str_Array = new string[] { Response, Error, string.Join("JOIN-", Cookies), "", "" };
                return str_Array;
            }
            catch (Exception ex)
            {
                string strLineNo = string.Empty;
                if (ex.StackTrace != null)
                {
                    if (ex.StackTrace.Contains("cs:line"))
                    {
                        strLineNo = ex.StackTrace.Substring(ex.StackTrace.IndexOf("cs:line"));
                    }
                }
                Error += "Unable to Connect Remote Server";
                Error = Error.StartsWith("Error") ? "21X1" + Error : "21X2" + Error;
                LogDetails += "<SENDREQUEST><STATUS>" + "X" + "</STATUS>"
                                            + "<MESSAGE>" + Error + "</MESSAGE>"
                                            + "<CERTPATH>" + CERTNAME + "</CERTPATH>"
                                            + "<LINENO>" + "APIIRCTC" + ".cs Method:" + ex.StackTrace.Substring(ex.StackTrace.LastIndexOf(":line") + 5) + "</LINENO>"
                                            + "<XML><![CDATA[" + ex.Message + "]]></XML></SENDREQUEST>";
                str_Array = new string[] { "", LogDetails, "", "", "" };

                return str_Array;
            }
        }

        [WebMethod(Description = "GRNNewSendRequest")]
        public bool SendHttpWebRequest(string TerminalId, string Seq, string pAppType, string strMethod, string strURL, string strRequestData, ref string strWebResponse, ref string strWebError)
        {
            try
            {
                string URL = "https://v3-api.grnconnect.com/";
                string Key = "9c38d0b7e35f017fbc714f537ba17878";
                if (string.IsNullOrEmpty(strURL))
                {
                    strWebError = "Url is Empty";
                    return false;
                }
                string strApiKey = Key;
                HttpWebRequest HttpReq = (HttpWebRequest)WebRequest.Create(URL + strURL);
                HttpReq.ContentType = "application/json";
                HttpReq.Headers.Add("api-key", strApiKey);
                HttpReq.Headers.Add("cache-control", "no-cache");
                HttpReq.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
                HttpReq.Accept = "application/json";
                HttpReq.Timeout = 180 * 1000;
                if (strMethod.ToUpper().Equals("GET"))
                {
                    HttpReq.Method = "GET";
                }
                else if (strMethod.ToUpper().Equals("POST"))
                {
                    HttpReq.Method = "POST";
                    byte[] lbPostBuffer = Encoding.Default.GetBytes(strRequestData);
                    HttpReq.ContentLength = lbPostBuffer.Length;
                    Stream PostStream = HttpReq.GetRequestStream();
                    PostStream.Write(lbPostBuffer, 0, lbPostBuffer.Length);
                    PostStream.Close();
                }
                else if (strMethod.ToUpper().Equals("DELETE"))
                {
                    HttpReq.Method = "DELETE";
                    //byte[] lbPostBuffer = Encoding.Default.GetBytes(strRequestData);
                    //HttpReq.ContentLength = lbPostBuffer.Length;
                    //Stream PostStream = HttpReq.GetRequestStream();
                    //PostStream.Write(lbPostBuffer, 0, lbPostBuffer.Length);
                    //PostStream.Close();
                }
                HttpWebResponse WebResponse = null;
                try
                {
                    WebResponse = (HttpWebResponse)HttpReq.GetResponse();
                }
                catch (Exception e)
                {
                    FieldInfo fieldInformation = HttpReq.GetType().GetField("_HttpResponse", BindingFlags.NonPublic | BindingFlags.Instance);
                    if (fieldInformation != null)
                    {
                        WebResponse = (HttpWebResponse)fieldInformation.GetValue(HttpReq);
                    }
                    if (WebResponse == null)
                    {
                        if (e.InnerException != null)
                        {
                            strWebResponse = e.InnerException.Message;
                            return false;
                        }
                        strWebResponse = e.Message;
                        return false;
                    }
                }
                // HttpWebResponse WebResponse = (HttpWebResponse)HttpReq.GetResponse();
                Stream responseStream = responseStream = WebResponse.GetResponseStream();
                if (WebResponse.ContentEncoding.ToLower().Contains("gzip"))
                {
                    responseStream = new GZipStream(responseStream, CompressionMode.Decompress);
                }
                else if (WebResponse.ContentEncoding.ToLower().Contains("deflate"))
                {
                    responseStream = new DeflateStream(responseStream, CompressionMode.Decompress);
                }

                StreamReader Reader = new StreamReader(responseStream, Encoding.Default);
                strWebResponse = Reader.ReadToEnd();
                WebResponse.Close();
                responseStream.Close();
                return true;
            }
            catch (Exception ex)
            {
                string strLineNo = string.Empty;
                if (ex.StackTrace != null)
                {
                    if (ex.StackTrace.Contains("cs:line"))
                    {
                        strLineNo = ex.StackTrace.Substring(ex.StackTrace.IndexOf("cs:line"));
                    }
                }
                string strException = "<Exception>" + ex.Message.ToString() + "</Exception>";
                // _clsCommon.WriteEventLog(strTerminalID, strSequenceNo, strException, "RQ", "Exception", "SendHttpWebRequest", "FAILED", "SendRequest");
                strWebError = strException;
                return false;
            }
        }

        public enum AppType
        {
            B2B,
            B2C,
            API,
            MOB,
            Service
        }
        private static bool ValidateRemoteCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors policyErrors)
        {
            if (Convert.ToBoolean("true"))
            {
                // allow any old dodgy certificate...
                return true;
            }
            else
            {
                return policyErrors == SslPolicyErrors.None;
            }
        }

        #region Private Functions
        private byte[] Convertbyte(string lstrInput, Encoder encoder)
        {
            byte[] queryByte = null;
            char[] charConvertArray = new char[lstrInput.Length];
            lstrInput.CopyTo(0, charConvertArray, 0, lstrInput.Length);
            int cout, bout;
            bool completed;
            queryByte = new byte[encoder.GetByteCount(charConvertArray, 0, charConvertArray.Length, true)];
            encoder.Convert(charConvertArray, 0, charConvertArray.Length, queryByte, 0, queryByte.Length, true, out cout, out bout, out completed);
            return queryByte;
        }
        #endregion



        [WebMethod(Description = "NL")]
        public string[] SendRequestwebclient(string URL, string Referer, string strbCookie, string Method, string strParameters,
            string strResponse)
        {
            string LogDetails = string.Empty;
            string[] str_Array = new string[5];
            string[] Cookies = new string[] { };
            string Response = "";
            string Error = "";
            try
            {


                DateTime dtnow = DateTime.Now;
                MyWebClient webclient = new MyWebClient();
                byte[] bytResponse = new byte[] { };
                string strCookieValue = string.Empty;
                webclient.Headers.Add("Content-Type", "application/x-www-form-urlencoded");
                webclient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.2; WOW64; rv:35.0) Gecko/20100101 Firefox/35.0");
                webclient.Headers.Add("Accept-Encoding", "gzip, deflate");
                webclient.Headers.Add("Cache-Control", "no-cache");
                if (Referer != "")
                    webclient.Headers.Add("Referer", Referer);
                string strCookie = string.Empty;
                strCookie += strbCookie + ";";
                if (!string.IsNullOrEmpty(strCookie))
                {
                    webclient.Headers["Cookie"] = strCookie.TrimEnd(';');
                }
                if (Method.Contains("GET"))
                {
                    bytResponse = webclient.DownloadData(URL);
                    strResponse = Encoding.ASCII.GetString(bytResponse);
                }
                if (Method.Contains("POST"))
                {
                    bytResponse = webclient.UploadData(URL, "POST", Encoding.ASCII.GetBytes(strParameters));
                    strResponse = Encoding.ASCII.GetString(bytResponse);
                }
                for (int i = 0; i < webclient.ResponseHeaders.Count; i++)
                {
                    if (webclient.ResponseHeaders.AllKeys[i].ToString().Contains("Set-Cookie"))
                    {
                        if (!string.IsNullOrEmpty(webclient.ResponseHeaders[HttpResponseHeader.SetCookie].ToString()))
                        {
                            strCookieValue = webclient.ResponseHeaders[HttpResponseHeader.SetCookie].ToString();
                            break;
                        }
                    }
                }
                strbCookie = strCookieValue;
                str_Array = new string[] { strResponse, Error, strCookieValue, "", "" };
                return str_Array;

            }
            catch (Exception ex)
            {
                string strLineNo = string.Empty;
                if (ex.StackTrace != null)
                {
                    if (ex.StackTrace.Contains("cs:line"))
                    {
                        strLineNo = ex.StackTrace.Substring(ex.StackTrace.IndexOf("cs:line"));
                    }
                }
                Error += "Unable to Connect Remote Server";
                Error = Error.StartsWith("Error") ? "21X1" + Error : "21X2" + Error;
                LogDetails += "<SENDREQUEST><STATUS>" + "X" + "</STATUS>"
                                            + "<MESSAGE>" + Error + "</MESSAGE>"
                                            + "<LINENO>" + "APIIRCTC" + ".cs Method:" + ex.StackTrace.Substring(ex.StackTrace.LastIndexOf(":line") + 5) + "</LINENO>"
                                            + "<XML><![CDATA[" + ex.Message + "]]></XML></SENDREQUEST>";
                str_Array = new string[] { "", LogDetails, "", "", "" };

                return str_Array;
            }

        }

        #region ¦¦¦ SendRequest Amadeus V4.0
        [WebMethod(Description = "Send Request For Amadeus V4.0")]
        public bool AmadeusSendQueryV4Post(string Seq, string SOAPVERSION, string SoapVersion, string URL_1A, string WSAP,
            string Credt, string RQ, string Token, ref string RS)
        {
            string strParseResult = string.Empty;
            string lstrError = string.Empty;
            try
            {
                string URLF = URL_1A;
                if (SOAPVERSION.Equals("4"))
                {
                    URLF = URL_1A + WSAP;
                }

                HttpWebRequest webRequest = (HttpWebRequest)HttpWebRequest.Create(URLF);

                //string strFinalQuery = string.Empty;
                webRequest.Credentials = CredentialCache.DefaultNetworkCredentials;
                string[] strArrCredentials = Credt.Split('/');
                webRequest.Proxy = null;
                webRequest.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
                webRequest.Method = "POST";
                webRequest.ContentType = "text/xml; charset=utf-8";
                if (SOAPVERSION.Equals("2"))
                {
                    webRequest.Headers.Add("SOAPAction:\"http://webservices.amadeus.com/" + WSAP + "/" + Token + "\"");
                }
                if (SOAPVERSION.Equals("4"))
                {
                    webRequest.Headers.Add("SOAPAction:\"http://webservices.amadeus.com/" + Token + "\"");
                }
                //strFinalQuery = "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">";
                //strFinalQuery += "<s:Header>";
                //if (URL.Contains("VLSSLQ_06_1_1A"))
                //{
                //    strFinalQuery += "<aws:SessionId xmlns:aws=\"http://webservices.amadeus.com/definitions\"></aws:SessionId>";
                //}
                //else
                //{
                //    strFinalQuery += "<s:Session>";
                //    strFinalQuery += "<awsec:SessionId xmlns:awsec=\"http://webservices.amadeus.com/definitions\">" + strArrCredentials[0].ToString() + "</awsec:SessionId>";
                //    strFinalQuery += "<awsec:SequenceNumber xmlns:awsec=\"http://webservices.amadeus.com/definitions\">" + strArrCredentials[2].ToString() + "</awsec:SequenceNumber>";
                //    strFinalQuery += "<awsec:SecurityToken xmlns:awsec=\"http://webservices.amadeus.com/definitions\">" + strArrCredentials[1].ToString() + "</awsec:SecurityToken>";
                //    strFinalQuery += "</s:Session>";
                //}
                //strFinalQuery += "</s:Header>";
                //strFinalQuery += "<s:Body xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">";
                //strFinalQuery += RQ;
                //strFinalQuery += "</s:Body>";
                //strFinalQuery += "</s:Envelope>";
                //byte[] queryByte = Convertbyte(Seq, strFinalQuery, Encoding.UTF8.GetEncoder());
                byte[] queryByte = Convertbyte(Seq, RQ, Encoding.UTF8.GetEncoder());
                webRequest.ContentLength = queryByte.Length;

                Stream strmRequestStream;
                try
                {
                    strmRequestStream = webRequest.GetRequestStream();
                }
                catch (Exception ex)
                {
                    if (ex.InnerException != null)
                    {
                        RS = ex.InnerException.Message;
                    }
                    RS = ex.Message;
                    return false;
                }
                strmRequestStream.Write(queryByte, 0, queryByte.Length);
                HttpWebResponse webResponse = null;
                try
                {
                    webResponse = (HttpWebResponse)webRequest.GetResponse();
                }
                catch (Exception e)
                {
                    FieldInfo fieldInformation = webRequest.GetType().GetField("_HttpResponse", BindingFlags.NonPublic | BindingFlags.Instance);
                    if (fieldInformation != null)
                    {
                        webResponse = (HttpWebResponse)fieldInformation.GetValue(webRequest);
                    }
                    if (webResponse == null)
                    {
                        strmRequestStream.Close();
                        if (e.InnerException != null)
                        {
                            RS = e.InnerException.Message;
                        }
                        return false;
                    }
                }

                Stream strmResponseStream = strmResponseStream = webResponse.GetResponseStream();
                if (webResponse.ContentEncoding.ToLower().Contains("gzip"))
                {
                    strmResponseStream = new GZipStream(strmResponseStream, CompressionMode.Decompress);
                }
                else if (webResponse.ContentEncoding.ToLower().Contains("deflate"))
                {
                    strmResponseStream = new DeflateStream(strmResponseStream, CompressionMode.Decompress);
                }
                StreamReader strmReader = new StreamReader(strmResponseStream, Encoding.Default);

                strParseResult = strmReader.ReadToEnd();

                strmReader.Close();
                strmRequestStream.Close();
                strmResponseStream.Close();
                RS = strParseResult;
                //    Logging.StoreLog(Terminal, Seq, StoreType.Xml,
                //LogType.E, pAppType, "<INPUTOUTPUT><REQUEST>" + strFinalQuery.ToString().Replace("<?xml version=\"1.0\" encoding=\"utf-8\"?>", "")
                //                   + "</REQUEST><RESPONSE>" + RS + "</RESPONSE><DURATION>" + "</DURATION>" + "</INPUTOUTPUT>",
                //                   "InternalPurposeLog", "1A", "InternalPurposeLog", null, false, Level.BelowHigh);
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }



        private byte[] Convertbyte(string strSequenceNo, string lstrInput, Encoder encoder)
        {
            byte[] queryByte = null;
            try
            {
                char[] charConvertArray = new char[lstrInput.Length];
                lstrInput.CopyTo(0, charConvertArray, 0, lstrInput.Length);
                int cout, bout;
                bool completed;
                queryByte = new byte[encoder.GetByteCount(charConvertArray, 0, charConvertArray.Length, true)];
                encoder.Convert(charConvertArray, 0, charConvertArray.Length, queryByte, 0, queryByte.Length, true, out cout, out bout, out completed);
            }
            catch (Exception ex)
            {
                string strLineNo = string.Empty;
                if (ex.StackTrace != null)
                {
                    if (ex.StackTrace.Contains("cs:line"))
                    {
                        strLineNo = ex.StackTrace.Substring(ex.StackTrace.IndexOf("cs:line"));
                    }
                }
            }
            return queryByte;
        }
        #endregion

        [WebMethod(Description = "Send Request For Spice,Indigo,Airasia,Tiger,AirPeagasus,Flydubai,Aircosta,Air India Express")]
        public string[] SendRequestForPG(string PGFlag, string TranUrl, string data,
                                                 string strResponce)
        {
            //ref string strResponse, ref string strErrorReturn
            string[] rstr_ParseResult = new string[4];
            try
            {
                if (PGFlag.ToString().ToUpper().Trim() == "C" || PGFlag.ToString().ToUpper().Trim() == "N")
                {
                    System.IO.StreamWriter myWriter = null;
                    System.Net.HttpWebRequest objRequest = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(TranUrl);//send data using objxmlhttp object
                    objRequest.Method = "POST";
                    objRequest.ContentLength = data.Length;
                    objRequest.ContentType = "application/x-www-form-urlencoded";//to set content type
                    myWriter = new System.IO.StreamWriter(objRequest.GetRequestStream());
                    myWriter.Write(data);
                    myWriter.Close();
                    System.Net.HttpWebResponse objResponse = (System.Net.HttpWebResponse)objRequest.GetResponse();

                    using (System.IO.StreamReader sr = new System.IO.StreamReader(objResponse.GetResponseStream()))
                    {
                        strResponce = sr.ReadToEnd();

                    }
                    rstr_ParseResult = new string[] { strResponce, "", "SendRequestForPG" + "Level0", "" };
                    return rstr_ParseResult;
                }
                else if (PGFlag.ToString().ToUpper().Trim() == "I")
                {
                    System.Net.HttpWebRequest objRequestNew = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(TranUrl);
                    {
                        objRequestNew.Method = "POST";
                        objRequestNew.ContentLength = data.Length;
                        objRequestNew.ContentType = "application/x-www-form-urlencoded";//to set content type
                        StreamWriter myWriter = new System.IO.StreamWriter(objRequestNew.GetRequestStream());
                        myWriter.Write(data);
                        myWriter.Close();
                        using (System.Net.HttpWebResponse objResponse = (System.Net.HttpWebResponse)objRequestNew.GetResponse())
                        {
                            using (System.IO.StreamReader sr = new System.IO.StreamReader(objResponse.GetResponseStream()))
                            {
                                strResponce = sr.ReadToEnd();

                            }
                        }
                    }
                    rstr_ParseResult = new string[] { strResponce, "", "SendRequestForPG" + "Level0", "" };
                    return rstr_ParseResult;
                }
            }
            catch (Exception ex)
            {
                rstr_ParseResult = new string[] { "", ex.ToString(), "SendRequestForPG" + "Level-1", "" };
                return rstr_ParseResult;
            }
            rstr_ParseResult = new string[] { strResponce, "", "SendRequestForPG" + "Level0", "" };
            return rstr_ParseResult;
        }




        private string PrettyPrint(string XML)
        {
            string Result = string.Empty;
            try
            {
                StringWriter strWriter = new StringWriter();
                XmlTextWriter txtWriter = new XmlTextWriter(strWriter);
                XmlDocument xmlDoc = new XmlDocument();
                // Load the XmlDocument with the XML.
                xmlDoc.LoadXml(XML);
                txtWriter.Formatting = Formatting.Indented;
                txtWriter.IndentChar = '\t';
                txtWriter.Indentation = 1;
                // Write the XML into a formatting XmlTextWriter
                xmlDoc.WriteTo(txtWriter);
                Result = strWriter.ToString();
                txtWriter.Close();
            }
            catch (Exception ex)
            {
            }
            return Result;
        }

        #region ClearTrip
        [WebMethod(Description = "SendClearTrip")]
        public bool SendHttpWebRequestClearTrip(string strTerminalID, string strSequenceNo, string strMethod, string strURL, string strRequestData, ref string strWebResponse, ref string strWebError)
        {
            try
            {
                if (string.IsNullOrEmpty(strURL))
                {
                    strWebError = "Url is Empty";
                    return false;
                }

                HttpWebRequest HttpReq = (HttpWebRequest)WebRequest.Create(strURL);
                HttpReq.Headers.Add("X-CT-API-KEY", "b3a14b90b9046230e8abddc81f1766b7");
                HttpReq.Headers.Add("X-CT-SOURCETYPE", "API");
                HttpReq.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
                HttpReq.Headers.Add(HttpRequestHeader.AcceptLanguage, "en-us,en;q=0.5");
                HttpReq.UserAgent = "Mozilla/5.0 (Windows NT 5.1; rv:18.0) Gecko/20100101 Firefox/18.0";
                HttpReq.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
                HttpReq.ContentType = "application/x-www-form-urlencoded";
                HttpReq.Timeout = 180 * 1000;

                if (strMethod.ToUpper().Equals("GET"))
                {
                    HttpReq.Method = "GET";
                }
                else if (strMethod.ToUpper().Equals("POST"))
                {
                    HttpReq.Method = "POST";
                    byte[] lbPostBuffer = Encoding.Default.GetBytes(strRequestData);
                    HttpReq.ContentLength = lbPostBuffer.Length;

                    Stream PostStream = HttpReq.GetRequestStream();
                    PostStream.Write(lbPostBuffer, 0, lbPostBuffer.Length);
                    PostStream.Close();
                }
                else if (strMethod.ToUpper().Equals("DELETE"))
                {
                    HttpReq.Method = "DELETE";
                }
                HttpWebResponse WebResponse = null;
                try
                {
                    WebResponse = (HttpWebResponse)HttpReq.GetResponse();
                }
                catch (Exception e)
                {
                    FieldInfo fieldInformation = HttpReq.GetType().GetField("_HttpResponse", BindingFlags.NonPublic | BindingFlags.Instance);
                    if (fieldInformation != null)
                    {
                        WebResponse = (HttpWebResponse)fieldInformation.GetValue(HttpReq);
                    }
                    if (WebResponse == null)
                    {
                        if (e.InnerException != null)
                        {
                            strWebResponse = e.InnerException.Message;
                            return false;
                        }
                        strWebResponse = e.Message;
                        return false;
                    }
                }
                // HttpWebResponse WebResponse = (HttpWebResponse)HttpReq.GetResponse();
                Stream responseStream = responseStream = WebResponse.GetResponseStream();
                if (WebResponse.ContentEncoding.ToLower().Contains("gzip"))
                {
                    responseStream = new GZipStream(responseStream, CompressionMode.Decompress);
                }
                else if (WebResponse.ContentEncoding.ToLower().Contains("deflate"))
                {
                    responseStream = new DeflateStream(responseStream, CompressionMode.Decompress);
                }

                StreamReader Reader = new StreamReader(responseStream, Encoding.Default);
                strWebResponse = Reader.ReadToEnd();
                WebResponse.Close();
                responseStream.Close();
                return true;
            }
            catch (Exception ex)
            {
                string strLineNo = string.Empty;
                if (ex.StackTrace != null)
                {
                    if (ex.StackTrace.Contains("cs:line"))
                    {
                        strLineNo = ex.StackTrace.Substring(ex.StackTrace.IndexOf("cs:line"));
                    }
                }
                string strException = "<Exception>" + ex.Message.ToString() + "</Exception>";
                //_clsCommon.WriteEventLog(strTerminalID, strSequenceNo, strException, "RQ", "Exception", "SendHttpWebRequest", "FAILED", "SendRequest");
                strWebError = strException;
                return false;
            }
        }
        #endregion

        #region DOTWReq
        [WebMethod(Description = "SendDOTW")]
        public bool SendRequestDOTW(string Input, ref string Response, ref string Error)
        {
            try
            {
                string LIVEURL = "http://us.dotwconnect.com/gateway.dotw";
                //UserId=Fahad007&Password=226%40OLA&CompanyCode=688645&customer_remember=on
                HttpWebRequest httpwebRequest = (HttpWebRequest)HttpWebRequest.Create(LIVEURL);
                httpwebRequest.Credentials = CredentialCache.DefaultNetworkCredentials;
                httpwebRequest.Proxy = null;
                httpwebRequest.KeepAlive = false;
                httpwebRequest.ProtocolVersion = HttpVersion.Version10;
                httpwebRequest.ServicePoint.ConnectionLimit = 1;
                httpwebRequest.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
                httpwebRequest.Method = "POST";
                httpwebRequest.ContentType = "text/xml; charset=utf-8";
                // httpwebRequest.Pa
                //httpwebRequest.Headers.Add("SOAPAction", strSoapAction);
                httpwebRequest.Accept = "text/xml";
                byte[] queryByte = Convertbyte(Input, Encoding.UTF8.GetEncoder());
                httpwebRequest.ContentLength = queryByte.Length;
                #region Write Request
                Stream strmRequestStream;
                try
                {
                    strmRequestStream = httpwebRequest.GetRequestStream();
                }
                catch (Exception ex)
                {
                    if (ex.InnerException != null)
                    {
                        Error = ex.InnerException.Message;
                        return false;
                    }
                    return false;
                }
                strmRequestStream.Write(queryByte, 0, queryByte.Length);
                #endregion

                HttpWebResponse webResponse = null;
                try
                {
                    webResponse = (HttpWebResponse)httpwebRequest.GetResponse();
                    // webResponse.ContentType = "application/zip";
                }
                catch (Exception e)
                {
                    FieldInfo fieldInformation = httpwebRequest.GetType().GetField("_HttpResponse", BindingFlags.NonPublic | BindingFlags.Instance);
                    if (fieldInformation != null)
                    {
                        webResponse = (HttpWebResponse)fieldInformation.GetValue(httpwebRequest);
                    }
                    if (webResponse == null)
                    {
                        strmRequestStream.Close();
                        if (e.InnerException != null)
                        {
                            Error = e.InnerException.Message;
                            return false;
                        }
                        Error = e.Message;
                        return false;
                    }
                }
                Stream strmResponseStream = strmResponseStream = webResponse.GetResponseStream();
                if (webResponse.ContentEncoding.ToLower().Contains("gzip"))
                {
                    strmResponseStream = new GZipStream(strmResponseStream, CompressionMode.Decompress);
                }
                else if (webResponse.ContentEncoding.ToLower().Contains("deflate"))
                {
                    strmResponseStream = new DeflateStream(strmResponseStream, CompressionMode.Decompress);
                }
                StreamReader strmReader = new StreamReader(strmResponseStream, Encoding.Default);
                Response = strmReader.ReadToEnd();
                strmReader.Close();
                strmRequestStream.Close();
                strmResponseStream.Close();
                return true;
            }
            catch (Exception ex)
            {

                throw ex;
            }
        }
        #endregion

        #region HotelBedsReq
        [WebMethod(Description = "SendHotelBeds")]
        private bool SendHttpWebRequestHotelBeds(string strMethod, string strURL, string strRequestData, ref string strWebResponse, ref string strWebError)
        {
            try
            {
                if (string.IsNullOrEmpty(strURL))
                {
                    strWebError = "Url is Empty";
                    return false;
                }
                //if (strBookFlag.ToString().Contains("0"))
                //{
                //    SWSHotel.HotelBeds1.Service1 _clsHotelBeds = new SWSHotel.HotelBeds1.Service1();

                //    strWebResponse = _clsHotelBeds.SendHttpWebRequest(strURL, strMethod, strRequestData);
                //    //SWSHotel.TravPaxProxy.Service1 _clsTravPaxApi = new SWSHotel.TravPaxProxy.Service1();
                //    //strWebResponse = _clsTravPaxApi.SendRequest(strURL, "POST", "", strRequestData);

                //    //SWSHotel.iphelp.Service1 _clsTravocoApi = new SWSHotel.iphelp.Service1();
                //    //strResponse = _clsTravocoApi.SendRequest(strUrl, strMethod, strSoapAction, strRequest.ToString());
                //    return true;
                //}
                HttpWebRequest httpwebRequest = (HttpWebRequest)HttpWebRequest.Create(strURL);
                httpwebRequest.Credentials = CredentialCache.DefaultNetworkCredentials;
                httpwebRequest.Proxy = null;
                httpwebRequest.KeepAlive = false;
                httpwebRequest.ProtocolVersion = HttpVersion.Version10;
                httpwebRequest.ServicePoint.ConnectionLimit = 1;
                httpwebRequest.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
                httpwebRequest.Method = strMethod;
                httpwebRequest.ContentType = "text/xml; charset=utf-8";
                //httpwebRequest.Headers.Add("SOAPAction", strSoapAction);
                httpwebRequest.Accept = "text/xml";
                byte[] queryByte = Convertbyte(strRequestData, Encoding.UTF8.GetEncoder());
                httpwebRequest.ContentLength = queryByte.Length;

                #region Write Request
                Stream strmRequestStream;
                try
                {
                    strmRequestStream = httpwebRequest.GetRequestStream();
                }
                catch (Exception ex)
                {
                    if (ex.InnerException != null)
                    {
                        strWebError = ex.InnerException.Message;
                        return false;
                    }
                    strWebError = ex.InnerException.Message;
                    return false;
                }
                strmRequestStream.Write(queryByte, 0, queryByte.Length);
                #endregion

                HttpWebResponse webResponse = null;
                try
                {
                    webResponse = (HttpWebResponse)httpwebRequest.GetResponse();
                }
                catch (Exception e)
                {
                    FieldInfo fieldInformation = httpwebRequest.GetType().GetField("_HttpResponse", BindingFlags.NonPublic | BindingFlags.Instance);
                    if (fieldInformation != null)
                    {
                        webResponse = (HttpWebResponse)fieldInformation.GetValue(httpwebRequest);
                    }
                    if (webResponse == null)
                    {
                        strmRequestStream.Close();
                        if (e.InnerException != null)
                        {
                            strWebError = e.InnerException.Message;
                            return false;
                        }
                        strWebError = e.Message;
                        return false;
                    }
                }
                Stream strmResponseStream = strmResponseStream = webResponse.GetResponseStream();
                if (webResponse.ContentEncoding.ToLower().Contains("gzip"))
                {
                    strmResponseStream = new GZipStream(strmResponseStream, CompressionMode.Decompress);
                }
                else if (webResponse.ContentEncoding.ToLower().Contains("deflate"))
                {
                    strmResponseStream = new DeflateStream(strmResponseStream, CompressionMode.Decompress);
                }
                StreamReader strmReader = new StreamReader(strmResponseStream, Encoding.Default);
                strWebResponse = strmReader.ReadToEnd();
                strmReader.Close();
                strmRequestStream.Close();
                strmResponseStream.Close();
                return true;
            }
            catch (Exception ex)
            {
                string strLineNo = string.Empty;
                if (ex.StackTrace != null)
                {
                    if (ex.StackTrace.Contains("cs:line"))
                    {
                        strLineNo = ex.StackTrace.Substring(ex.StackTrace.IndexOf("cs:line"));
                    }
                }
                string strException = "<Exception>" + ex.Message.ToString() + "</Exception>";
                // _clsCommon.WriteEventLog(strTerminalID, strSequenceNo, strException, "RQ", "Exception", "SendHttpWebRequest", "FAILED", "SendRequest");
                strWebError = strException;
                return false;
            }
        }
        #endregion

        #region TouricoReq
        [WebMethod(Description = "SendTourico")]
        public bool SendRequestTourico(string strURL, string strMethod, string strSoapAction, string strRequestData, ref string strWebResponse, ref string strWebError)
        {
            try
            {
                if (string.IsNullOrEmpty(strURL))
                {
                    strWebError = "Url is Empty";
                    return false;
                }
                HttpWebRequest HttpReq = (HttpWebRequest)WebRequest.Create(strURL);
                HttpReq.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
                HttpReq.Headers.Add(HttpRequestHeader.AcceptLanguage, "en-us,en;q=0.5");
                HttpReq.UserAgent = "Mozilla/5.0 (Windows NT 5.1; rv:18.0) Gecko/20100101 Firefox/18.0";
                HttpReq.Accept = "application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
                HttpReq.ContentType = "text/xml; charset=utf-8";
                if (!string.IsNullOrEmpty(strSoapAction))
                    HttpReq.Headers.Add("SoapAction", strSoapAction);
                HttpReq.Timeout = 180 * 1000;

                if (strMethod.ToUpper().Equals("GET"))
                {
                    HttpReq.Method = "GET";
                }
                else if (strMethod.ToUpper().Equals("POST"))
                {
                    HttpReq.Method = "POST";
                    byte[] lbPostBuffer = Encoding.Default.GetBytes(strRequestData);
                    HttpReq.ContentLength = lbPostBuffer.Length;

                    Stream PostStream = HttpReq.GetRequestStream();
                    PostStream.Write(lbPostBuffer, 0, lbPostBuffer.Length);
                    PostStream.Close();
                }
                else if (strMethod.ToUpper().Equals("DELETE"))
                {
                    HttpReq.Method = "DELETE";
                }

                HttpWebResponse WebResponse = null;
                try
                {
                    WebResponse = (HttpWebResponse)HttpReq.GetResponse();
                }
                catch (Exception e)
                {
                    FieldInfo fieldInformation = HttpReq.GetType().GetField("_HttpResponse", BindingFlags.NonPublic | BindingFlags.Instance);
                    if (fieldInformation != null)
                    {
                        WebResponse = (HttpWebResponse)fieldInformation.GetValue(HttpReq);
                    }
                    if (WebResponse == null)
                    {
                        if (e.InnerException != null)
                        {
                            strWebResponse = e.InnerException.Message;
                            return false;
                        }
                        strWebResponse = e.Message;
                        return false;
                    }
                }

                Stream rsStream = WebResponse.GetResponseStream();
                if (WebResponse.ContentEncoding.ToLower().Contains("gzip"))
                {
                    rsStream = new GZipStream(rsStream, CompressionMode.Decompress);
                }
                else if (WebResponse.ContentEncoding.ToLower().Contains("deflate"))
                {
                    rsStream = new DeflateStream(rsStream, CompressionMode.Decompress);
                }

                //StreamReader Reader = new StreamReader(rsStream, Encoding.Default);//before
                StreamReader Reader = new StreamReader(rsStream, Encoding.UTF8);
                strWebResponse = Reader.ReadToEnd();
                WebResponse.Close();
                rsStream.Close();
                return true;
            }
            catch (Exception ex)
            {
                string strLineNo = string.Empty;
                if (ex.StackTrace != null)
                {
                    if (ex.StackTrace.Contains("cs:line"))
                    {
                        strLineNo = ex.StackTrace.Substring(ex.StackTrace.IndexOf("cs:line"));
                    }
                }
                string strException = "<Exception>" + ex.Message.ToString() + "</Exception>";
                //_clsCommon.WriteEventLog(strTerminalID, strSequenceNo, strException, "RQ", "Exception", "SendHttpWebRequest", "FAILED", "SendRequest");
                strWebError = strException;
                return false;
            }
        }
        #endregion

        #region TravcoReq
        [WebMethod(Description = "SendTravco")]
        public bool SendRequestTravco(string strUrl, string strMethod, string strSoapAction, string strRequest, ref string strResponse, ref string strError)
        {
            try
            {
                //if (strBookFlag.ToString().Contains("0"))
                //{
                //    SWSHotel.TravcoProxy.Service1 _clsTravocoApi = new SWSHotel.TravcoProxy.Service1();
                //    strResponse = _clsTravocoApi.SendRequest(strUrl, strMethod, strSoapAction, strRequest.ToString());

                //    //SWSHotel.iphelp.Service1 _clsTravocoApi = new SWSHotel.iphelp.Service1();
                //    //strResponse = _clsTravocoApi.SendRequest(strUrl, strMethod, strSoapAction, strRequest.ToString());
                //    return true;
                //}
                string strRequestURL = strUrl;
                HttpWebRequest httpwebRequest = (HttpWebRequest)HttpWebRequest.Create(strRequestURL);
                httpwebRequest.Credentials = CredentialCache.DefaultNetworkCredentials;
                httpwebRequest.Proxy = null;
                httpwebRequest.KeepAlive = false;
                httpwebRequest.ProtocolVersion = HttpVersion.Version10;
                httpwebRequest.ServicePoint.ConnectionLimit = 1;
                httpwebRequest.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
                httpwebRequest.Method = strMethod;
                httpwebRequest.ContentType = "text/xml; charset=utf-8";
                //httpwebRequest.Headers.Add("SOAPAction", strSoapAction);
                httpwebRequest.Accept = "text/xml";
                byte[] queryByte = Convertbyte(strRequest, Encoding.UTF8.GetEncoder());
                httpwebRequest.ContentLength = queryByte.Length;

                #region Write Request
                Stream strmRequestStream;
                try
                {
                    strmRequestStream = httpwebRequest.GetRequestStream();
                }
                catch (Exception ex)
                {
                    if (ex.InnerException != null)
                    {
                        strError = ex.InnerException.Message;
                        return false;
                    }
                    strError = ex.InnerException.Message;
                    return false;
                }
                strmRequestStream.Write(queryByte, 0, queryByte.Length);
                #endregion

                HttpWebResponse webResponse = null;
                try
                {
                    webResponse = (HttpWebResponse)httpwebRequest.GetResponse();
                    //webResponse.ContentType = "application/zip";

                }
                catch (Exception e)
                {
                    FieldInfo fieldInformation = httpwebRequest.GetType().GetField("_HttpResponse", BindingFlags.NonPublic | BindingFlags.Instance);
                    if (fieldInformation != null)
                    {
                        webResponse = (HttpWebResponse)fieldInformation.GetValue(httpwebRequest);
                    }
                    if (webResponse == null)
                    {
                        strmRequestStream.Close();
                        if (e.InnerException != null)
                        {
                            strError = e.InnerException.Message;
                            return false;
                        }
                        strError = e.Message;
                        return false;
                    }
                }
                Stream strmResponseStream = strmResponseStream = webResponse.GetResponseStream();
                if (webResponse.ContentEncoding.ToLower().Contains("gzip"))
                {
                    strmResponseStream = new GZipStream(strmResponseStream, CompressionMode.Decompress);
                }
                else if (webResponse.ContentEncoding.ToLower().Contains("deflate"))
                {
                    strmResponseStream = new DeflateStream(strmResponseStream, CompressionMode.Decompress);
                }
                StreamReader strmReader = new StreamReader(strmResponseStream, Encoding.UTF8);
                strResponse = strmReader.ReadToEnd();
                strmReader.Close();
                strmRequestStream.Close();
                strmResponseStream.Close();
                return true;
            }
            catch (Exception ex)
            {
                strError = ex.Message.ToString();
                return false;
            }
        }
        #endregion

        [WebMethod(Description = "PrannamSendRequest")]
        public bool SendRequestPrannam(String Request, string _URL, string Soapaction, string CRSID, ref string Response, ref string Error)
        {
            try
            {

                HttpWebRequest httpwebRequest = (HttpWebRequest)HttpWebRequest.Create(_URL);
                httpwebRequest.Credentials = CredentialCache.DefaultNetworkCredentials;
                //httpwebRequest.Proxy = null;
                httpwebRequest.KeepAlive = false;
                System.Net.ServicePointManager.Expect100Continue = false;
                httpwebRequest.ProtocolVersion = HttpVersion.Version11;
                httpwebRequest.ServicePoint.ConnectionLimit = 1;
                httpwebRequest.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
                httpwebRequest.Method = "POST";
                httpwebRequest.ContentType = "text/xml; charset=utf-8";
                httpwebRequest.Headers.Add("SOAPAction", Soapaction);
                httpwebRequest.Accept = "text/xml";
                httpwebRequest.Timeout = 300000;
                byte[] queryByte = Convertbyte(Request, Encoding.UTF8.GetEncoder());
                httpwebRequest.ContentLength = queryByte.Length;

                #region Write Request
                Stream strmRequestStream;
                try
                {
                    strmRequestStream = httpwebRequest.GetRequestStream();
                }
                catch (Exception ex)
                {
                    if (ex.InnerException != null)
                    {
                        Error = ex.InnerException.Message;
                        return false;
                    }
                    Error = ex.Message.ToString();
                    return false;
                }
                strmRequestStream.Write(queryByte, 0, queryByte.Length);
                #endregion

                HttpWebResponse webResponse = null;
                try
                {
                    webResponse = (HttpWebResponse)httpwebRequest.GetResponse();
                }
                catch (Exception e)
                {
                    FieldInfo fieldInformation = httpwebRequest.GetType().GetField("_HttpResponse", BindingFlags.NonPublic | BindingFlags.Instance);
                    if (fieldInformation != null)
                    {
                        webResponse = (HttpWebResponse)fieldInformation.GetValue(httpwebRequest);
                    }
                    if (webResponse == null)
                    {
                        strmRequestStream.Close();
                        if (e.InnerException != null)
                        {
                            Error = e.InnerException.Message;
                            return false;
                        }
                        Error = e.Message;
                        return false;
                    }
                }

                Stream strmResponseStream = strmResponseStream = webResponse.GetResponseStream();
                if (webResponse.ContentEncoding.ToLower().Contains("gzip"))
                {
                    strmResponseStream = new GZipStream(strmResponseStream, CompressionMode.Decompress);
                }
                else if (webResponse.ContentEncoding.ToLower().Contains("deflate"))
                {
                    strmResponseStream = new DeflateStream(strmResponseStream, CompressionMode.Decompress);
                }
                StreamReader strmReader = new StreamReader(strmResponseStream, Encoding.Default);
                Response = strmReader.ReadToEnd();
                strmReader.Close();
                strmRequestStream.Close();
                strmResponseStream.Close();
                return true;
            }
            catch (Exception ex)
            {
                string strLineNo = string.Empty;
                if (ex.StackTrace != null)
                {
                    if (ex.StackTrace.Contains("cs:line"))
                    {
                        strLineNo = ex.StackTrace.Substring(ex.StackTrace.IndexOf("cs:line"));
                    }
                }
                // Error = string.Format(ERDetails.Unable_to_connect_remote_server_IX01, CRSID);
                return false;
            }
        }

        [WebMethod(Description = "CarSendRequest")]
        public bool SendRequestCar(String Request, string _URL, string Soapaction, string CRSID, ref string Response, ref string Error)
        {
            try
            {
                //  Request = File.ReadAllText(@"E:\abc.txt"); 
                //  Request = GetSoapEnvelope(Request);
                HttpWebRequest httpwebRequest = (HttpWebRequest)HttpWebRequest.Create(_URL);
                httpwebRequest.Credentials = CredentialCache.DefaultNetworkCredentials;
                //httpwebRequest.Proxy = null;
                httpwebRequest.KeepAlive = false;
                System.Net.ServicePointManager.Expect100Continue = false;
                httpwebRequest.ProtocolVersion = HttpVersion.Version11;
                httpwebRequest.ServicePoint.ConnectionLimit = 1;
                httpwebRequest.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
                httpwebRequest.Method = "POST";
                httpwebRequest.ContentType = "application/x-www-form-urlencoded; charset=UTF-8";
                //httpwebRequest.Headers.Add("SOAPAction", Soapaction);
                httpwebRequest.Accept = "application/json, text/javascript, */*; q=0.01";
                httpwebRequest.Timeout = 300000;
                byte[] queryByte = Convertbyte(Request, Encoding.UTF8.GetEncoder());
                httpwebRequest.ContentLength = queryByte.Length;

                #region Write Request
                Stream strmRequestStream;
                try
                {
                    strmRequestStream = httpwebRequest.GetRequestStream();
                }
                catch (Exception ex)
                {
                    if (ex.InnerException != null)
                    {
                        Error = ex.InnerException.Message;
                        return false;
                    }
                    Error = ex.Message.ToString();
                    return false;
                }
                strmRequestStream.Write(queryByte, 0, queryByte.Length);
                #endregion

                HttpWebResponse webResponse = null;
                try
                {
                    webResponse = (HttpWebResponse)httpwebRequest.GetResponse();
                }
                catch (Exception e)
                {
                    FieldInfo fieldInformation = httpwebRequest.GetType().GetField("_HttpResponse", BindingFlags.NonPublic | BindingFlags.Instance);
                    if (fieldInformation != null)
                    {
                        webResponse = (HttpWebResponse)fieldInformation.GetValue(httpwebRequest);
                    }
                    if (webResponse == null)
                    {
                        strmRequestStream.Close();
                        if (e.InnerException != null)
                        {
                            Error = e.InnerException.Message;
                            return false;
                        }
                        Error = e.Message;
                        return false;
                    }
                }

                Stream strmResponseStream = strmResponseStream = webResponse.GetResponseStream();
                if (webResponse.ContentEncoding.ToLower().Contains("gzip"))
                {
                    strmResponseStream = new GZipStream(strmResponseStream, CompressionMode.Decompress);
                }
                else if (webResponse.ContentEncoding.ToLower().Contains("deflate"))
                {
                    strmResponseStream = new DeflateStream(strmResponseStream, CompressionMode.Decompress);
                }
                StreamReader strmReader = new StreamReader(strmResponseStream, Encoding.Default);
                Response = strmReader.ReadToEnd();
                strmReader.Close();
                strmRequestStream.Close();
                strmResponseStream.Close();
                return true;
            }
            catch (Exception ex)
            {
                string strLineNo = string.Empty;
                if (ex.StackTrace != null)
                {
                    if (ex.StackTrace.Contains("cs:line"))
                    {
                        strLineNo = ex.StackTrace.Substring(ex.StackTrace.IndexOf("cs:line"));
                    }
                }
                // Error = string.Format(ERDetails.Unable_to_connect_remote_server_IX01, CRSID);
                return false;
            }
        }

        [WebMethod(Description = "BajajSendRequest")]
        public bool SendHTTPRequestBajaj(string strAgentId, string strTerminalId, string strSequenceNo, string strRequestURL, string strRequestMethod, string strRequestXml, string strCrsName, ref string strWebResponse)
        {
            try
            {
                # region Old method
                //MSXML2.XMLHTTP xmlHTTP = new MSXML2.XMLHTTP();
                ////MSXML2.ServerXMLHTTP xmlHTTP = new MSXML2.ServerXMLHTTP();
                //xmlHTTP.open("POST", strRequestURL, false, "", "");
                //xmlHTTP.setRequestHeader("SOAPAction", "http://tempuri.org/");
                //xmlHTTP.setRequestHeader("Content-Type", "text/xml; charset=utf-8");
                //if (strRequestURL.StartsWith("http"))
                //{
                //    xmlHTTP.setRequestHeader("Timeout", "1000");
                //}
                //xmlHTTP.send(strRequestXml.ToString());
                //strWebResponse = xmlHTTP.responseText.ToString();
                //return true;
                #endregion

                string strURL = "http://webservices.bajajallianz.com/BjazTravelWebservice/BjazTravelWebservicePort?wsdl";

                string strTimeout = "180000";//ConfigurationSettings.AppSettings["TimeOut"].ToString();
                HttpWebRequest HttpReq = (HttpWebRequest)WebRequest.Create(strURL);
                HttpReq.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
                HttpReq.Headers.Add(HttpRequestHeader.AcceptLanguage, "en-us,en;q=0.5");
                HttpReq.Headers.Add("SOAPAction", "http://tempuri.org/");
                HttpReq.ContentType = "text/xml; charset=utf-8";
                HttpReq.Timeout = Convert.ToInt32(strTimeout);

                Stream sRequestStream = default(Stream);
                if (strRequestMethod.ToUpper().Equals("GET"))
                {
                    HttpReq.Method = "GET";
                }
                else if (strRequestMethod.ToUpper().Equals("POST"))
                {
                    HttpReq.Method = "POST";
                    byte[] lbPostBuffer = Encoding.Default.GetBytes(strRequestXml);
                    //byte[] lbPostBuffer = Convertbyte(strAgentId, strTerminalId, strSequenceNo, strRequestXml, Encoding.UTF8.GetEncoder());
                    HttpReq.ContentLength = lbPostBuffer.Length;

                    sRequestStream = HttpReq.GetRequestStream();
                    sRequestStream.Write(lbPostBuffer, 0, lbPostBuffer.Length);
                    sRequestStream.Close();
                }
                else if (strRequestMethod.ToUpper().Equals("DELETE"))
                {
                    HttpReq.Method = "DELETE";
                }

                HttpWebResponse httpwebResponse = null;
                try
                {
                    httpwebResponse = (HttpWebResponse)HttpReq.GetResponse();
                }
                catch (Exception e)
                {
                    FieldInfo fieldInformation = HttpReq.GetType().GetField("_HttpResponse", BindingFlags.NonPublic | BindingFlags.Instance);
                    if (fieldInformation != null)
                    {
                        httpwebResponse = (HttpWebResponse)fieldInformation.GetValue(HttpReq);
                    }
                    if (httpwebResponse == null)
                    {
                        sRequestStream.Close();
                        if (e.InnerException != null)
                        {
                            strWebResponse = e.InnerException.Message;
                            return false;
                        }
                        strWebResponse = e.Message;
                        return false;
                    }
                }

                Stream sResponseStream = httpwebResponse.GetResponseStream();
                if (httpwebResponse.ContentEncoding.ToLower().Contains("gzip"))
                {
                    sResponseStream = new GZipStream(sResponseStream, CompressionMode.Decompress);
                }
                else if (httpwebResponse.ContentEncoding.ToLower().Contains("deflate"))
                {
                    sResponseStream = new DeflateStream(sResponseStream, CompressionMode.Decompress);
                }

                StreamReader srReader = new StreamReader(sResponseStream, Encoding.Default);
                strWebResponse = srReader.ReadToEnd();
                srReader.Close();
                httpwebResponse.Close();
                sResponseStream.Close();
                return true;
            }
            catch (Exception ex)
            {
                strWebResponse = "Unable to connect " + strCrsName.ToString() + " Server";
                //_clsCommon.insertException(strAgentId, strTerminalId, strSequenceNo, "BJ", "Request", "X", "Exception Occured while Sending HTTP Request", "clsBajajAllianz", "SendHTTPRequest", GetExceptionXML(ex));
                return false;
            }
        }



        [WebMethod(Description = "RedBusInvokeGetRequest")]
        public string RedInvokeGetRequest(string requestUrl, ref string strError)
        {
            string baseUrl = "http://api.seatseller.travel";
            string completeUrl = baseUrl + requestUrl;
            string header = "";
            try
            {
                HttpWebRequest request1 = WebRequest.Create(completeUrl) as HttpWebRequest;

                request1.ContentType = @"application/json";
                request1.Method = @"GET";
                header = formHeader(completeUrl, "GET");
                request1.Headers.Add(HttpRequestHeader.Authorization, header);

                HttpWebResponse httpWebResponse = (HttpWebResponse)request1.GetResponse();
                StreamReader reader = new
                StreamReader(httpWebResponse.GetResponseStream());
                string responseString = reader.ReadToEnd();
                return responseString;
            }
            catch (WebException ex)
            {
                if (ex.Response == null)
                {
                    strError = ex.Message.ToString();
                    return "";
                }
                using (var reader = new StreamReader(ex.Response.GetResponseStream()))
                {
                    // strError = GettingError(reader.ReadToEnd());
                    return "";
                }
            }
            catch (Exception ex)
            {
                strError = "(Server)" + ex.Message.ToString();
                return "";
            }
        }

        [WebMethod(Description = "RedBusInvokePostRequest")]
        public string RedInvokePostRequest(string requestUrl, string requestBody, ref string strError)
        {
            string baseUrl = "http://api.seatseller.travel";
            string completeUrl = baseUrl + requestUrl;
            try
            {

                HttpWebRequest request = WebRequest.Create(completeUrl) as HttpWebRequest;
                request.ContentType = @"application/json";
                request.Method = @"POST";
                request.Headers.Add(HttpRequestHeader.Authorization, formHeader(completeUrl, "POST"));
                StreamWriter requestWriter = new StreamWriter(request.GetRequestStream());
                requestWriter.Write(requestBody);
                requestWriter.Close();
                HttpWebResponse webResponse = (HttpWebResponse)request.GetResponse();

                StreamReader responseReader = new StreamReader(webResponse.GetResponseStream());
                return responseReader.ReadToEnd();

            }
            catch (WebException ex)
            {
                if (ex.Response == null)
                {
                    strError = "(Server)" + ex.Message.ToString();
                    return "";
                }
                using (var reader = new StreamReader(ex.Response.GetResponseStream()))
                {
                    //strError = GettingError(reader.ReadToEnd());
                    return "";
                }
            }
            catch (Exception ex)
            {
                strError = "(Server)" + ex.Message.ToString();
                return "";
            }
        }

        [WebMethod(Description = "BusEtravelSendRequest")]
        public bool SendRequestEtravelBus(StringBuilder strRequest, string hsCredential, ref string strResponse, ref string ErrorDesc)
        {
            try
            {
                TextReader txtread = new StringReader(strRequest.ToString());
                XDocument xdoc = XDocument.Load(txtread);
                XNamespace xmlns = "http://tempuri.org/";
                var result = (from un in xdoc.Descendants(xmlns + "WebClientRequestNetworkCredentials").AsEnumerable()
                              select new
                              {
                                  RequestURL = un.Element(xmlns + "strRequestURL").Value,
                                  UserName = un.Element(xmlns + "strNetworkUserName").Value,
                                  Password = un.Element(xmlns + "strNetworkPassword").Value,
                                  Method = un.Element(xmlns + "strRequestMethod").Value,
                                  InputData = un.Element(xmlns + "strRequestInput").Value

                              }).ToArray();


                WebClient wcRQ = new WebClient();
                byte[] bytarrRequest = new byte[] { };
                byte[] bytarrResponse = new byte[] { };
                wcRQ.Credentials = new NetworkCredential(result[0].UserName.ToString(), result[0].Password.ToString());
                wcRQ.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
                wcRQ.Headers.Add("content-type", "application/json");
                wcRQ.Headers.Add("Timeout", "60000");
                string strSoapAction = "";
                if (!string.IsNullOrEmpty(strSoapAction))
                    wcRQ.Headers.Add("SOAPAction", strSoapAction);
                try
                {
                    if (result[0].Method.ToString().ToUpper().Equals("GET"))
                    {
                        bytarrResponse = wcRQ.DownloadData(result[0].RequestURL.ToString());
                    }
                    else if (result[0].Method.ToString().ToUpper().Equals("POST"))
                    {
                        bytarrRequest = Encoding.ASCII.GetBytes(result[0].InputData.ToString());
                        bytarrResponse = wcRQ.UploadData(result[0].RequestURL.ToString(), bytarrRequest);
                    }
                    else
                    {
                        ErrorDesc = "Invalid Http Request.";
                        return false;
                    }
                }
                catch (Exception ex)
                {
                    ErrorDesc = ex.Message.ToString();
                }
                strResponse = Encoding.ASCII.GetString(bytarrResponse);


                strResponse = strResponse.Replace("&", "&amp;");
                string status = strResponse.Contains("true") ? "true" : "false";
                StringBuilder sbResponse = new StringBuilder();
                sbResponse.Append("<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">");
                sbResponse.Append("<soap:Body>");
                sbResponse.Append("<WebClientRequestNetworkCredentialsResponse xmlns=\"http://tempuri.org/\">");
                sbResponse.Append("<WebClientRequestNetworkCredentialsResult>" + status + "</WebClientRequestNetworkCredentialsResult>");
                sbResponse.Append("<strResponseOutput>" + strResponse + "</strResponseOutput>");
                sbResponse.Append("<strErrorOutput>" + ErrorDesc + "</strErrorOutput>");
                sbResponse.Append("</WebClientRequestNetworkCredentialsResponse>");
                sbResponse.Append("</soap:Body>");
                sbResponse.Append("</soap:Envelope>");

                strResponse = sbResponse.ToString();
                if (!strResponse.Contains("true"))
                {
                    ErrorDesc = strResponse.Contains("Oops Blocking failed from operator end, Please try with other seat or bus") ? "Requested bus is sold out,Please try with other seat or bus" : ErrorDesc;
                    ErrorDesc = strResponse.Contains("No Buses found to match request") ? "No Buses found for this request" : ErrorDesc;
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                ErrorDesc = ex.Message.ToString();
                return false;
            }
        }

        private string formHeader(string requestUrl, string methodType)
        {
            OAuthBase oauthBase = new OAuthBase();
            string consumerKey = "UgZC1WNa0YLYhe2OGULkYfN433sAVT";
            string consumerSecret = "JLcKhrKg4SoyEc2r9SXRm8bsGZowzV";
            string normalisedUrl = string.Empty;
            string normalisedParams = string.Empty;
            string authHeader = string.Empty;
            string timeStamp = oauthBase.GenerateTimeStamp();
            string nonce = oauthBase.GenerateNonce();
            string requestWithAuth = oauthBase.GenerateSignature(new Uri(requestUrl), consumerKey, consumerSecret,
                "", "", methodType, timeStamp, nonce, OAuthBase.SignatureTypes.HMACSHA1, out normalisedUrl, out normalisedParams, out authHeader);
            string finalAuthHeader = "OAuth oauth_nonce=\"" + nonce + "\",oauth_consumer_key=\"UgZC1WNa0YLYhe2OGULkYfN433sAVT\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\""
               + timeStamp + "\",oauth_version=\"1.0\",oauth_signature=\"" + HttpUtility.UrlEncode(requestWithAuth) + "\"";
            return finalAuthHeader;
        }

        private CookieContainer cookiecontainer;
        [WebMethod(Description = "SendRequestWithHttp1")]
        public string[] SendRequestWithHttp(string URL, string sessionid, string method, string parameter)
        {
            string LogDetails = string.Empty;
            string[] str_Array = new string[5];
            string[] Cookies = new string[] { };
            string Response = "";
            string Error = "";
            try
            {

                string ip = ConfigurationManager.AppSettings["IPROUTE"] != null && ConfigurationManager.AppSettings["IPROUTE"].ToString() != "" ? ConfigurationManager.AppSettings["IPROUTE"].ToString() : "";

                if (!string.IsNullOrEmpty(ip))
                {

                    Route_Ip.Service1 _ip = new Route_Ip.Service1();
                    string[] strWebResponse1 = _ip.SendRequestWithHttp(URL, sessionid, method, parameter);

                    str_Array = strWebResponse1;
                    return str_Array;
                }



                //string strPath = System.Web.Hosting.HostingEnvironment.MapPath(@"~/App_Data/Certifigate/booksecure.net.crt");
                //X509Certificate Cert = X509Certificate.CreateFromCertFile(strPath);
                //ServicePointManager.ServerCertificateValidationCallback += ValidateServerCertificate;
                ServicePointManager.ServerCertificateValidationCallback += new RemoteCertificateValidationCallback(ValidateRemoteCertificate);
                DateTime dtnow = DateTime.Now;
                string strWebResponse = ""; string strWebCookie = ""; string strWebError = string.Empty;
                HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(URL);
                httpWebRequest.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
                httpWebRequest.ContentType = "application/x-www-form-urlencoded";
                httpWebRequest.CookieContainer = cookiecontainer;
                //httpWebRequest.MaximumAutomaticRedirections = 50;


                httpWebRequest.UserAgent = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.2.13) Gecko/20101203 Firefox/5.0";
                httpWebRequest.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,application/json, text/javascript,*/*;q=0.8";
                //httpWebRequest.ClientCertificates.Add(Cert);
                httpWebRequest.Credentials = CredentialCache.DefaultCredentials;
                httpWebRequest.ProtocolVersion = HttpVersion.Version11;
                httpWebRequest.KeepAlive = false;
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                httpWebRequest.Method = method;

                httpWebRequest.Timeout = 100000;
                //string strCookie = string.Empty;
                //foreach (DictionaryEntry hshvalue in hshHeaders)
                //{
                //    strCookie += hshvalue.Key.ToString() + "=" + hshvalue.Value.ToString() + ";";
                //}
                if (!string.IsNullOrEmpty(sessionid))
                {
                    httpWebRequest.Headers["Cookie"] = sessionid.TrimEnd(';');
                }

                byte[] bytarrParam = Encoding.ASCII.GetBytes(parameter);
                Stream strmInput = null;
                if (method.Contains("POST"))
                {
                    httpWebRequest.ContentLength = bytarrParam.Length;   //Count bytes to send
                    strmInput = httpWebRequest.GetRequestStream();
                    strmInput.Write(bytarrParam, 0, bytarrParam.Length);
                }//Send it

                HttpWebResponse httpWwebResponse = (HttpWebResponse)httpWebRequest.GetResponse();
                Stream strmOutput = httpWwebResponse.GetResponseStream();

                if (httpWwebResponse.ContentEncoding.ToLower().Contains("gzip"))
                {
                    strmOutput = new GZipStream(strmOutput, CompressionMode.Decompress);
                }
                else if (httpWwebResponse.ContentEncoding.ToLower().Contains("deflate"))
                {
                    strmOutput = new DeflateStream(strmOutput, CompressionMode.Decompress);
                }
                if (httpWwebResponse.Headers[HttpResponseHeader.SetCookie] != null)
                {
                    for (int i = 0; i < httpWwebResponse.Headers.Count; i++)
                    {
                        if (httpWwebResponse.Headers.GetKey(i).Contains("Set-Cookie"))
                        {
                            strWebCookie += httpWwebResponse.Headers[i] + "`";
                        }
                    }
                }
                strWebCookie = strWebCookie.TrimEnd('`');
                if (httpWwebResponse.ResponseUri.AbsoluteUri != null)
                    strWebError = httpWwebResponse.ResponseUri.AbsoluteUri;

                string strHtmlResponse = string.Empty;
                StreamReader strmrdrResponse;
                using (strmrdrResponse = new StreamReader(strmOutput))
                {
                    strHtmlResponse = strmrdrResponse.ReadToEnd();
                    // Close and clean up the StreamReader
                    strmrdrResponse.Close();
                }
                strWebResponse = strHtmlResponse;


                str_Array = new string[] { strWebResponse, strWebError, strWebCookie, "", "" };
                return str_Array;

            }
            catch (Exception ex)
            {
                string strLineNo = string.Empty;
                if (ex.StackTrace != null)
                {
                    if (ex.StackTrace.Contains("cs:line"))
                    {
                        strLineNo = ex.StackTrace.Substring(ex.StackTrace.IndexOf("cs:line"));
                    }
                }
                Error += "Unable to Connect Remote Server";
                Error = Error.StartsWith("Error") ? "21X1" + Error : "21X2" + Error;
                LogDetails += "<SENDREQUEST><STATUS>" + "X" + "</STATUS>"
                                            + "<MESSAGE>" + Error + "</MESSAGE>"
                                            + "<LINENO>" + "IXSEND" + ".cs Method:" + ex.StackTrace.Substring(ex.StackTrace.LastIndexOf(":line") + 5) + "</LINENO>"
                                            + "<XML><![CDATA[" + ex.Message + "]]></XML></SENDREQUEST>";
                str_Array = new string[] { "", LogDetails, "", "", "" };

                return str_Array;
            }
        }

        [WebMethod(Description = "SendRequest_FOR_CEBU")]
        public string[] SendRequestWithHttp_new(string Method, string _URL, string parameter, string sessionid, string contentype, string allowredirect, string Authorizationid)
        {
            string[] str_Array = new string[5];
            string Error = "";
            string LogDetails = string.Empty;
            try
            {
                DateTime dtnow = DateTime.Now;

                string strWebResponse = ""; string strWebCookie = ""; string strWebError = string.Empty;


                HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(_URL);
                httpWebRequest.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
                if (contentype == "n")
                    httpWebRequest.ContentType = "application/x-www-form-urlencoded";
                else
                    httpWebRequest.ContentType = "application/json; charset=utf-8";
                if (allowredirect == "s")
                    httpWebRequest.AllowAutoRedirect = false;
                if (Authorizationid != "")
                    httpWebRequest.Headers.Add("authorization", Authorizationid);
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
                //ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                httpWebRequest.UserAgent = "Mozilla/5.0 (Windows NT 6.2; WOW64; rv:35.0) Gecko/20100101 Firefox/35.0";
                httpWebRequest.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,application/json, text/javascript,*/*;q=0.8";
                httpWebRequest.Credentials = CredentialCache.DefaultCredentials;
                httpWebRequest.Proxy = null;
                httpWebRequest.KeepAlive = false;
                System.Net.ServicePointManager.Expect100Continue = false;
                httpWebRequest.ProtocolVersion = HttpVersion.Version11;
                httpWebRequest.Method = Method;// hshTable["strMethod"].ToString();
                string strCookie = string.Empty;
                strCookie += sessionid + ";";
                if (!string.IsNullOrEmpty(strCookie))
                {
                    httpWebRequest.Headers["Cookie"] = strCookie.TrimEnd(';');
                }

                byte[] bytarrParam = Encoding.ASCII.GetBytes(parameter);
                Stream strmInput = null;
                if (Method.ToString().Contains("POST"))
                {
                    httpWebRequest.ContentLength = bytarrParam.Length;   //Count bytes to send
                    strmInput = httpWebRequest.GetRequestStream();
                    strmInput.Write(bytarrParam, 0, bytarrParam.Length);
                }//Send it

                HttpWebResponse httpWwebResponse = (HttpWebResponse)httpWebRequest.GetResponse();
                Stream strmOutput = httpWwebResponse.GetResponseStream();

                if (httpWwebResponse.ContentEncoding.ToLower().Contains("gzip"))
                {
                    strmOutput = new GZipStream(strmOutput, CompressionMode.Decompress);
                }
                else if (httpWwebResponse.ContentEncoding.ToLower().Contains("deflate"))
                {
                    strmOutput = new DeflateStream(strmOutput, CompressionMode.Decompress);
                }
                if (httpWwebResponse.Headers[HttpResponseHeader.SetCookie] != null)
                {
                    for (int i = 0; i < httpWwebResponse.Headers.Count; i++)
                    {
                        if (httpWwebResponse.Headers.GetKey(i).Contains("Set-Cookie"))
                        {
                            strWebCookie += httpWwebResponse.Headers[i] + "`";
                        }
                    }
                }
                strWebCookie = strWebCookie.TrimEnd('`');
                if (httpWwebResponse.ResponseUri.AbsoluteUri != null)
                    strWebError = httpWwebResponse.ResponseUri.AbsoluteUri;

                string strHtmlResponse = string.Empty;
                StreamReader strmrdrResponse;
                using (strmrdrResponse = new StreamReader(strmOutput))
                {
                    strHtmlResponse = strmrdrResponse.ReadToEnd();
                    // Close and clean up the StreamReader
                    strmrdrResponse.Close();
                }
                strWebResponse = strHtmlResponse;
                str_Array = new string[] { strWebResponse, strWebError, strWebCookie, "", "" };
                return str_Array;

                // hshTable["strCredential"] = strWebCookie;



                // hshTable["strResponse"] = strWebResponse;
                //// InsertLog(_AgentDetails, TerminalID, lstrSequence, lAppType, dtnow, Method, hshTable);
                // return true;
            }
            catch (Exception ex)
            {
                string strLineNo = string.Empty;
                if (ex.StackTrace != null)
                {
                    if (ex.StackTrace.Contains("cs:line"))
                    {
                        strLineNo = ex.StackTrace.Substring(ex.StackTrace.IndexOf("cs:line"));
                    }
                }
                Error += "Unable to Connect Remote Server";
                Error = Error.StartsWith("Error") ? "21X1" + Error : "21X2" + Error;
                LogDetails += "<SENDREQUEST><STATUS>" + "X" + "</STATUS>"
                                            + "<MESSAGE>" + Error + "</MESSAGE>"
                                            + "<LINENO>" + "IXSEND" + ".cs Method:" + ex.StackTrace.Substring(ex.StackTrace.LastIndexOf(":line") + 5) + "</LINENO>"
                                            + "<XML><![CDATA[" + ex.Message + "]]></XML></SENDREQUEST>";
                str_Array = new string[] { "", LogDetails, "", "", "" };

                return str_Array;
            }
        }


        #region Sendrequest-Scrapping
        [WebMethod(Description = "Scrap WebRequest (Gzip, SSL)")]
        public bool GetResponseWebReqWSWG(string strSiteName, string strRequestUrl, string strAccessMethod,
        string strPostParameters, string strCookie, string strFunctionName, string strCertificateName, ref string strWebResponse, ref string strWebCookie, ref string strWebError)
        {
            try
            {
                string strCertificatePath = ConfigurationManager.AppSettings["FolderLog"].ToString() + "Certificates\\";
                strWebResponse = strWebCookie = strWebError = string.Empty;

                //LogRequestXml(strSiteName, strRequestUrl, strPostParameters, strAccessMethod, hshHeaders, strFunctionName);

                X509Certificate Cert = X509Certificate.CreateFromCertFile(strCertificatePath + strCertificateName);
                ServicePointManager.ServerCertificateValidationCallback += new RemoteCertificateValidationCallback(ValidateRemoteCertificate);
                HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(strRequestUrl);
                httpWebRequest.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
                httpWebRequest.ContentType = "application/x-www-form-urlencoded";
                httpWebRequest.CookieContainer = cookiecontainer;
                //httpWebRequest.MaximumAutomaticRedirections = 50;


                httpWebRequest.UserAgent = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.2.13) Gecko/20101203 Firefox/5.0";
                httpWebRequest.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,application/json, text/javascript,*/*;q=0.8";
                httpWebRequest.ClientCertificates.Add(Cert);
                httpWebRequest.Credentials = CredentialCache.DefaultCredentials;
                httpWebRequest.Method = strAccessMethod;
                if (strFunctionName.Contains("6EAgentHome"))
                {
                    httpWebRequest.AllowAutoRedirect = false;
                    // httpWebRequest.Referer = "https://book.goindigo.in";
                }
                httpWebRequest.Timeout = Convert.ToInt32(ConfigurationManager.AppSettings["ScrapTimeout"].ToString());
                //string strCookie = string.Empty;
                //foreach (DictionaryEntry hshvalue in hshHeaders)
                //{
                //    strCookie += hshvalue.Key.ToString() + "=" + hshvalue.Value.ToString() + ";";
                //}
                if (!string.IsNullOrEmpty(strCookie))
                {
                    httpWebRequest.Headers["Cookie"] = strCookie.TrimEnd(';');
                }

                byte[] bytarrParam = Encoding.ASCII.GetBytes(strPostParameters);
                Stream strmInput = null;
                if (strAccessMethod.Contains("POST"))
                {
                    httpWebRequest.ContentLength = bytarrParam.Length;   //Count bytes to send
                    strmInput = httpWebRequest.GetRequestStream();
                    strmInput.Write(bytarrParam, 0, bytarrParam.Length);
                }//Send it

                HttpWebResponse httpWwebResponse = (HttpWebResponse)httpWebRequest.GetResponse();
                Stream strmOutput = httpWwebResponse.GetResponseStream();

                if (httpWwebResponse.ContentEncoding.ToLower().Contains("gzip"))
                {
                    strmOutput = new GZipStream(strmOutput, CompressionMode.Decompress);
                }
                else if (httpWwebResponse.ContentEncoding.ToLower().Contains("deflate"))
                {
                    strmOutput = new DeflateStream(strmOutput, CompressionMode.Decompress);
                }
                if (httpWwebResponse.Headers[HttpResponseHeader.SetCookie] != null)
                {
                    for (int i = 0; i < httpWwebResponse.Headers.Count; i++)
                    {
                        if (httpWwebResponse.Headers.GetKey(i).Contains("Set-Cookie"))
                        {
                            strWebCookie += httpWwebResponse.Headers[i] + "`";
                        }
                    }
                }
                strWebCookie = strWebCookie.TrimEnd('`');
                if (httpWwebResponse.ResponseUri.AbsoluteUri != null)
                    strWebError = httpWwebResponse.ResponseUri.AbsoluteUri;

                string strHtmlResponse = string.Empty;
                StreamReader strmrdrResponse;
                using (strmrdrResponse = new StreamReader(strmOutput))
                {
                    strHtmlResponse = strmrdrResponse.ReadToEnd();
                    // Close and clean up the StreamReader
                    strmrdrResponse.Close();
                }
                strWebResponse = strHtmlResponse;
                return true;
            }
            catch (Exception ex)
            {
                string strLineNo = string.Empty;
                if (ex.StackTrace != null)
                {
                    if (ex.StackTrace.Contains("cs:line"))
                    {
                        strLineNo = ex.StackTrace.Substring(ex.StackTrace.IndexOf("cs:line"));
                    }
                }
                //_clsCommon.insertException(strAgentId, strTerminalId, strSequenceNo, strSiteName, "Request", "X", "Exception Occured while Sending Request(Gzip, ssl)", "clsScraping", "GetResponseWebReqWSWG(Gzip, ssl)", ex.Message.ToString() + strLineNo);
                strWebError = "Unable to Connect Remote Server";
                return false;
            }
        }
        [WebMethod(Description = "Scrap WebRequest (Gzip, No SSL)")]
        public bool GetResponseWebReqWoSWG(string strSiteName, string strRequestUrl, string strAccessMethod, string strParameters, string strCookie, string strFunctionName, ref string strWebResponse, ref string strWebCookie, ref string strWebError)
        {
            try
            {
                if (string.IsNullOrEmpty(strRequestUrl))
                {
                    strWebError = "Url is Empty";
                    return false;
                }

                strWebResponse = string.Empty;
                strWebCookie = string.Empty;
                strWebError = string.Empty;
                //string strCookie = string.Empty;

                HttpWebRequest HttpReq = (HttpWebRequest)WebRequest.Create(strRequestUrl);

                //LogRequestXml(strSiteName, strRequestUrl, strParameters, strAccessMethod, hshHeaders, strFunctionName);
                HttpReq.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
                HttpReq.Timeout = Convert.ToInt32(ConfigurationManager.AppSettings["ScrapTimeout"].ToString());
                HttpReq.ContentType = "application/x-www-form-urlencoded";
                HttpReq.UserAgent = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.2.13) Gecko/20101203 Firefox/3.6.13";
                //foreach (DictionaryEntry hshvalue in hshHeaders)
                //{
                //    strCookie += hshvalue.Key.ToString() + "=" + hshvalue.Value.ToString() + ";";
                //}
                if (!string.IsNullOrEmpty(strCookie))
                {
                    HttpReq.Headers["Cookie"] = strCookie.TrimEnd(';');
                }

                if (!string.IsNullOrEmpty(strParameters))
                {
                    HttpReq.Method = "POST";
                    byte[] lbPostBuffer = Encoding.Default.GetBytes(strParameters);

                    HttpReq.ContentLength = lbPostBuffer.Length;

                    Stream PostStream = HttpReq.GetRequestStream();
                    PostStream.Write(lbPostBuffer, 0, lbPostBuffer.Length);
                    PostStream.Close();
                }

                HttpWebResponse WebResponse = (HttpWebResponse)HttpReq.GetResponse();

                Stream responseStream = responseStream = WebResponse.GetResponseStream();
                if (WebResponse.ContentEncoding.ToLower().Contains("gzip"))
                {
                    responseStream = new GZipStream(responseStream, CompressionMode.Decompress);
                }
                else if (WebResponse.ContentEncoding.ToLower().Contains("deflate"))
                {
                    responseStream = new DeflateStream(responseStream, CompressionMode.Decompress);
                }
                if (WebResponse.Headers[HttpResponseHeader.SetCookie] != null)
                {
                    strWebCookie = WebResponse.Headers[HttpResponseHeader.SetCookie];
                }
                StreamReader Reader = new StreamReader(responseStream, Encoding.Default);
                string Html = Reader.ReadToEnd();
                strWebResponse = Html;
                WebResponse.Close();
                responseStream.Close();
                return true;
            }
            catch (Exception ex)
            {

                return false;
            }
        }

        //SpiceJet New Scrapping...
        [WebMethod(Description = "SG new Scrapping")]
        public bool SendRequestWithHttpNewForSG(string strAgentId, string strTerminalId, string strSequenceNo, string Method, string strSiteURL, string SESSIONID, string strRequest, ref string strResponseCookie, ref string strResponse, string contentype, string allowredirect, string Authorizationid)
        {
            try
            {
                DateTime dtnow = DateTime.Now;

                string strWebResponse = ""; string strWebCookie = ""; string strWebError = string.Empty;

                //string strURL = hshTable["Url"].ToString();
                HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(strSiteURL.ToString());
                httpWebRequest.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip, deflate, br");
                if (contentype == "n")
                    httpWebRequest.ContentType = "application/x-www-form-urlencoded";
                else
                    httpWebRequest.ContentType = "application/json; charset=utf-8";
                if (allowredirect == "s")
                    httpWebRequest.AllowAutoRedirect = false;
                if (Authorizationid != "")
                    httpWebRequest.Headers.Add("authorization", Authorizationid);
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
                httpWebRequest.UserAgent = "Mozilla/5.0 (Windows NT 6.2; WOW64; rv:35.0) Gecko/20100101 Firefox/35.0";
                httpWebRequest.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,application/json, text/javascript,*/*;q=0.8";
                httpWebRequest.Credentials = CredentialCache.DefaultCredentials;
                httpWebRequest.Proxy = null;
                httpWebRequest.KeepAlive = false;
                System.Net.ServicePointManager.Expect100Continue = false;
                httpWebRequest.ProtocolVersion = HttpVersion.Version11;
                httpWebRequest.Method = Method;
                string strCookie = string.Empty;
                strCookie += SESSIONID + ";";
                if (!string.IsNullOrEmpty(strCookie))
                {
                    httpWebRequest.Headers["Cookie"] = strCookie.TrimEnd(';');
                }

                byte[] bytarrParam = Encoding.ASCII.GetBytes(strRequest.ToString());
                Stream strmInput = null;
                if (Method.Contains("POST"))
                {
                    httpWebRequest.ContentLength = bytarrParam.Length;   //Count bytes to send
                    strmInput = httpWebRequest.GetRequestStream();
                    strmInput.Write(bytarrParam, 0, bytarrParam.Length);
                }//Send it

                HttpWebResponse httpWwebResponse = (HttpWebResponse)httpWebRequest.GetResponse();
                Stream strmOutput = httpWwebResponse.GetResponseStream();

                if (httpWwebResponse.ContentEncoding.ToLower().Contains("gzip"))
                {
                    strmOutput = new GZipStream(strmOutput, CompressionMode.Decompress);
                }
                else if (httpWwebResponse.ContentEncoding.ToLower().Contains("deflate"))
                {
                    strmOutput = new DeflateStream(strmOutput, CompressionMode.Decompress);
                }
                if (httpWwebResponse.Headers[HttpResponseHeader.SetCookie] != null)
                {
                    for (int i = 0; i < httpWwebResponse.Headers.Count; i++)
                    {
                        if (httpWwebResponse.Headers.GetKey(i).Contains("Set-Cookie"))
                        {
                            strWebCookie += httpWwebResponse.Headers[i] + "`";
                        }
                    }
                }
                strWebCookie = strWebCookie.TrimEnd('`');
                if (httpWwebResponse.ResponseUri.AbsoluteUri != null)
                    strWebError = httpWwebResponse.ResponseUri.AbsoluteUri;

                string strHtmlResponse = string.Empty;
                StreamReader strmrdrResponse;
                using (strmrdrResponse = new StreamReader(strmOutput))
                {
                    strHtmlResponse = strmrdrResponse.ReadToEnd();
                    // Close and clean up the StreamReader
                    strmrdrResponse.Close();
                }
                strWebResponse = strHtmlResponse;

                strResponseCookie = strWebCookie;

                strResponse = strWebResponse;
                return true;
            }
            catch (Exception ex)
            {
                string strLineNo = string.Empty;
                if (ex.StackTrace != null)
                {
                    if (ex.StackTrace.Contains("cs:line"))
                    {
                        strLineNo = ex.StackTrace.Substring(ex.StackTrace.IndexOf("cs:line"));
                    }
                }
                //_clsCommon.insertException(strAgentId, strTerminalId, strSequenceNo, "", "Request", "Z", "Exception Occured while SendRequestWithHttp_new", "clsScraping", "SendRequestWithHttp_new", "<RESPONSE><HTML><![CDATA[" + ex.Message.ToString().Trim() + "  " + strLineNo + "]]></HTML></RESPONSE>");
                return false;
            }
        }
        #endregion


        [WebMethod(Description = "SendHttpWebRequest_Rayna")]
        public string[] _SendHttpWebRequest(string strRequestData, string strURL, ref string strWebResponse, ref string strWebError)
        {
            string LogDetails = string.Empty;
            string[] str_Array = new string[5];
            string[] Cookies = new string[] { };
            string Response = "";
            string Error = "";
            try
            {
                string strMethod = "POST";
                if (string.IsNullOrEmpty(strURL))
                {
                    strWebError = "Url is Empty";
                    str_Array = new string[] { strWebResponse, strWebError, "", "", "" };
                    return str_Array;
                }
                HttpWebRequest HttpReq = (HttpWebRequest)WebRequest.Create(strURL);
                HttpReq.ContentType = "application/json";

                HttpReq.Accept = "application/json";
                HttpReq.Timeout = 180 * 1000;
                if (strMethod.ToUpper().Equals("GET"))
                {
                    HttpReq.Method = "GET";
                }
                else if (strMethod.ToUpper().Equals("POST"))
                {
                    HttpReq.Method = "POST";
                    byte[] lbPostBuffer = Encoding.Default.GetBytes(strRequestData);
                    HttpReq.ContentLength = lbPostBuffer.Length;
                    Stream PostStream = HttpReq.GetRequestStream();
                    PostStream.Write(lbPostBuffer, 0, lbPostBuffer.Length);
                    PostStream.Close();
                }
                else if (strMethod.ToUpper().Equals("DELETE"))
                {
                    HttpReq.Method = "DELETE";

                }
                HttpWebResponse WebResponse = null;
                try
                {
                    WebResponse = (HttpWebResponse)HttpReq.GetResponse();
                }
                catch (Exception e)
                {
                    FieldInfo fieldInformation = HttpReq.GetType().GetField("_HttpResponse", BindingFlags.NonPublic | BindingFlags.Instance);
                    if (fieldInformation != null)
                    {
                        WebResponse = (HttpWebResponse)fieldInformation.GetValue(HttpReq);
                    }
                    if (WebResponse == null)
                    {
                        if (e.InnerException != null)
                        {
                            strWebResponse = e.InnerException.Message;
                            str_Array = new string[] { "", strWebResponse, "", "", "" };
                            return str_Array;
                        }
                        strWebResponse = e.Message;
                        str_Array = new string[] { "", strWebResponse, "", "", "" };
                        return str_Array;
                    }
                }
                // HttpWebResponse WebResponse = (HttpWebResponse)HttpReq.GetResponse();
                Stream responseStream = responseStream = WebResponse.GetResponseStream();
                if (WebResponse.ContentEncoding.ToLower().Contains("gzip"))
                {
                    responseStream = new GZipStream(responseStream, CompressionMode.Decompress);
                }
                else if (WebResponse.ContentEncoding.ToLower().Contains("deflate"))
                {
                    responseStream = new DeflateStream(responseStream, CompressionMode.Decompress);
                }

                StreamReader Reader = new StreamReader(responseStream, Encoding.Default);
                strWebResponse = Reader.ReadToEnd();
                WebResponse.Close();
                responseStream.Close();
                str_Array = new string[] { strWebResponse, "", "", "", "" };
                return str_Array;
            }
            catch (Exception ex)
            {
                string strLineNo = string.Empty;
                if (ex.StackTrace != null)
                {
                    if (ex.StackTrace.Contains("cs:line"))
                    {
                        strLineNo = ex.StackTrace.Substring(ex.StackTrace.IndexOf("cs:line"));
                    }
                }
                string strException = "<Exception>" + ex.Message.ToString() + "</Exception>";
                strWebError = strException;
                str_Array = new string[] { "", strWebError, "", "", "" };
                return str_Array;
            }
        }

        [WebMethod(Description = "Common for Webclient for all Scraping")]
        public string[] webclient_SendRequest(string strRequestData, string strURL, string lstrSequence, string Method, string Referer, string Cookie)
        {

            string LogDetails = string.Empty;
            string[] str_Array = new string[5];
            string strResponse = string.Empty;
            try
            {
                DateTime dtnow = DateTime.Now;
                MyWebClient webclient = new MyWebClient();
                byte[] bytResponse = new byte[] { };
                string strCookieValue = string.Empty;
                webclient.Headers.Add("Content-Type", "application/x-www-form-urlencoded");
                webclient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.2; WOW64; rv:35.0) Gecko/20100101 Firefox/35.0");
                webclient.Headers.Add("Accept-Encoding", "gzip, deflate");
                webclient.Headers.Add("Cache-Control", "no-cache");
                if (Referer.ToString() != "")
                    webclient.Headers.Add("Referer", Referer);
                string strCookie = string.Empty;
                strCookie += Cookie + ";";
                if (!string.IsNullOrEmpty(strCookie))
                {
                    webclient.Headers["Cookie"] = strCookie.TrimEnd(';');
                }
                if (Method.Contains("GET"))
                {
                    bytResponse = webclient.DownloadData(strURL);
                    strResponse = Encoding.ASCII.GetString(bytResponse);
                }
                if (Method.Contains("POST"))
                {
                    bytResponse = webclient.UploadData(strURL, "POST", Encoding.ASCII.GetBytes(strRequestData));
                    strResponse = Encoding.ASCII.GetString(bytResponse);
                }

                for (int i = 0; i < webclient.ResponseHeaders.Count; i++)
                {
                    if (webclient.ResponseHeaders.AllKeys[i].ToString().Contains("Set-Cookie"))
                    {
                        if (!string.IsNullOrEmpty(webclient.ResponseHeaders[HttpResponseHeader.SetCookie].ToString()))
                        {
                            strCookieValue = webclient.ResponseHeaders[HttpResponseHeader.SetCookie].ToString();
                            break;
                        }
                    }
                }


                str_Array = new string[] { strResponse, "", strCookieValue, "", "" };
                return str_Array;

            }
            catch (Exception ex)
            {
                //Logging.StoreLog(TerminalID, lstrSequence, StoreType.Xml, LogType.X, lAppType, "",
                //    ex.StackTrace.Substring(ex.StackTrace.LastIndexOf(":line") + 5) + ex.Message.ToString(), "5J", (new StackTrace()).GetFrame(0).GetMethod().Name, ex, false, Level.BelowHigh);
                str_Array = new string[] { "", (ex.StackTrace.LastIndexOf(":line") + 5) + ex.Message.ToString(), "", "", "" };
                return str_Array;
            }
        }
        [WebMethod(Description = "Common for httpWebRequest for all Scraping")]
        public string[] httpWebRequest_SendRequest(string strRequestData, string URL, string Method, string Reqcookies, string contentype, string allowredirect)
        {
            string LogDetails = string.Empty;
            string[] str_Array = new string[5];
            try
            {
                DateTime dtnow = DateTime.Now;
                string strWebResponse = ""; string strWebCookie = ""; string strWebError = string.Empty;
                HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(URL);
                httpWebRequest.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
                if (contentype == "n")
                    httpWebRequest.ContentType = "application/x-www-form-urlencoded";
                else
                    httpWebRequest.ContentType = "application/json; charset=utf-8";
                if (allowredirect == "s")
                    httpWebRequest.AllowAutoRedirect = false;

                httpWebRequest.UserAgent = "Mozilla/5.0 (Windows NT 6.2; WOW64; rv:35.0) Gecko/20100101 Firefox/35.0";
                httpWebRequest.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,application/json, text/javascript,*/*;q=0.8";
                httpWebRequest.Credentials = CredentialCache.DefaultCredentials;
                httpWebRequest.Proxy = null;
                httpWebRequest.KeepAlive = false;
                System.Net.ServicePointManager.Expect100Continue = false;
                httpWebRequest.ProtocolVersion = HttpVersion.Version11;
                httpWebRequest.Method = Method;
                string strCookie = string.Empty;
                strCookie += Reqcookies + ";";
                if (!string.IsNullOrEmpty(strCookie))
                {
                    httpWebRequest.Headers["Cookie"] = strCookie.TrimEnd(';');
                }

                byte[] bytarrParam = Encoding.ASCII.GetBytes(strRequestData);
                Stream strmInput = null;
                if (Method.Contains("POST"))
                {
                    httpWebRequest.ContentLength = bytarrParam.Length;   //Count bytes to send
                    strmInput = httpWebRequest.GetRequestStream();
                    strmInput.Write(bytarrParam, 0, bytarrParam.Length);
                }//Send it

                HttpWebResponse httpWwebResponse = (HttpWebResponse)httpWebRequest.GetResponse();
                Stream strmOutput = httpWwebResponse.GetResponseStream();

                if (httpWwebResponse.ContentEncoding.ToLower().Contains("gzip"))
                {
                    strmOutput = new GZipStream(strmOutput, CompressionMode.Decompress);
                }
                else if (httpWwebResponse.ContentEncoding.ToLower().Contains("deflate"))
                {
                    strmOutput = new DeflateStream(strmOutput, CompressionMode.Decompress);
                }
                if (httpWwebResponse.Headers[HttpResponseHeader.SetCookie] != null)
                {
                    for (int i = 0; i < httpWwebResponse.Headers.Count; i++)
                    {
                        if (httpWwebResponse.Headers.GetKey(i).Contains("Set-Cookie"))
                        {
                            strWebCookie += httpWwebResponse.Headers[i] + "`";
                        }
                    }
                }
                strWebCookie = strWebCookie.TrimEnd('`');
                if (httpWwebResponse.ResponseUri.AbsoluteUri != null)
                    strWebError = httpWwebResponse.ResponseUri.AbsoluteUri;

                string strHtmlResponse = string.Empty;
                StreamReader strmrdrResponse;
                using (strmrdrResponse = new StreamReader(strmOutput))
                {
                    strHtmlResponse = strmrdrResponse.ReadToEnd();
                    // Close and clean up the StreamReader
                    strmrdrResponse.Close();
                }
                strWebResponse = strHtmlResponse;

                //hshTable["strCredential"] = strWebCookie;

                str_Array = new string[] { strWebResponse, "", strWebCookie, "", "" };
                return str_Array;


                //hshTable["strResponse"] = strWebResponse;
                //InsertLog(TerminalID, lstrSequence, lAppType, dtnow, Method, hshTable);
                //return true;
            }
            catch (Exception ex)
            {
                string strLineNo = string.Empty;
                if (ex.StackTrace != null)
                {
                    if (ex.StackTrace.Contains("cs:line"))
                    {
                        strLineNo = ex.StackTrace.Substring(ex.StackTrace.IndexOf("cs:line"));
                    }
                }
                str_Array = new string[] { "", "Unable to connect remote server", "", "", "" };
                return str_Array;
                //Logging.StoreLog(TerminalID, lstrSequence, StoreType.Xml, LogType.X, lAppType, "",
                //   strLineNo + ex.Message.ToString(), "5J", (new StackTrace()).GetFrame(0).GetMethod().Name, ex, false, Level.BelowHigh);


                //return false;
            }
        }

        [WebMethod(Description = "UpdateProductList for ding")]
        public string[] UpdateProductList(string Seq, string Username, string PassWd, ref Eztop.GetProductListResponse _GetProductListResponse)
        {
            string[] str_Array = new string[5];
            try
            {
                Eztop.EDTSManager _EDTSManager = new Eztop.EDTSManager();
                Eztop.GetProductListRequest _GetProductListRequest = new Eztop.GetProductListRequest()
                {
                    MessageID = Convert.ToInt32(Seq),
                    AuthenticationToken = new Eztop.AuthenticationToken()
                    {
                        AuthenticationID = Username,
                        AuthenticationPassword = PassWd,
                    }
                };
                _GetProductListResponse = _EDTSManager.GetProductList(_GetProductListRequest);

                str_Array = new string[] { "SUCCESS", "", "", "", "" };
            }
            catch (Exception ex)
            {
                //Logging.StoreLog(strTerminal, Seq, StoreType.Xml,
                //                    LogType.X, pAppType, "",
                //                    ex.StackTrace.Substring(ex.StackTrace.LastIndexOf(":line") + 5) + ex.Message.ToString(), "Ding", (new StackTrace()).GetFrame(0).GetMethod().Name, ex, false, Level.BelowHigh);
                str_Array = new string[] { "", ex.StackTrace.Substring(ex.StackTrace.LastIndexOf(":line") + 5) + ex.Message.ToString(), "", "", "" };
            }

            return str_Array;
        }

        [WebMethod(Description = "IsCountrySupportedByEzetop for ding")]
        public string[] IsCountrySupportedByEzetop(string Seq, string Username, string PassWd, string CountryIso, ref Eztop.IsCountrySupportedByEzeOperatorResponse _IsCountrySupportedByEzeOperatorResponse)
        {
            string[] str_Array = new string[5];
            try
            {
                Eztop.EDTSManager _EDTSManager = new Eztop.EDTSManager();
                Eztop.IsCountrySupportedByEzeOperatorRequest _IsCountrySupportedByEzeOperatorRequest = new Eztop.IsCountrySupportedByEzeOperatorRequest()
                {
                    AuthenticationToken = new Eztop.AuthenticationToken()
                    {
                        AuthenticationID = Username,
                        AuthenticationPassword = PassWd
                    },

                    CountryIso = CountryIso,
                    MessageId = Convert.ToInt32(Seq)
                };
                _IsCountrySupportedByEzeOperatorResponse = _EDTSManager.IsCountrySupportedByEzeOperator(_IsCountrySupportedByEzeOperatorRequest);

                str_Array = new string[] { "SUCCESS", "", "", "", "" };
            }
            catch (Exception ex)
            {
                //Logging.StoreLog(strTerminal, Seq, StoreType.Xml,
                //                    LogType.X, pAppType, "",
                //                    ex.StackTrace.Substring(ex.StackTrace.LastIndexOf(":line") + 5) + ex.Message.ToString(), "Ding", (new StackTrace()).GetFrame(0).GetMethod().Name, ex, false, Level.BelowHigh);
                str_Array = new string[] { "", ex.StackTrace.Substring(ex.StackTrace.LastIndexOf(":line") + 5) + ex.Message.ToString(), "", "", "" };
            }

            return str_Array;
        }

        [WebMethod(Description = "ValidatePhoneAccount for ding")]
        public string[] ValidatePhoneAccount(string Seq, string Username, string PassWd, string CountryIso, string CountryCode, string OperatorCode, string PhoneNumber, ref Eztop.ValidatePhoneAccountResponse _ValidatePhoneAccountResponse)
        {
            string[] str_Array = new string[5];
            try
            {
                Eztop.EDTSManager _EDTSManager = new Eztop.EDTSManager();
                Eztop.ValidatePhoneAccountRequest _ValidatePhoneAccountRequest = new Eztop.ValidatePhoneAccountRequest()
                {
                    AuthenticationToken = new Eztop.AuthenticationToken()
                    {
                        AuthenticationID = Username,
                        AuthenticationPassword = PassWd
                    },

                    Amount = 0d,
                    CountryCode = CountryCode,
                    MessageID = Convert.ToInt32(Seq),
                    OperatorCode = OperatorCode,
                    PhoneNumber = PhoneNumber
                };
                _ValidatePhoneAccountResponse = _EDTSManager.ValidatePhoneAccount(_ValidatePhoneAccountRequest);

                str_Array = new string[] { "SUCCESS", "", "", "", "" };
            }
            catch (Exception ex)
            {
                //Logging.StoreLog(strTerminal, Seq, StoreType.Xml,
                //                    LogType.X, pAppType, "",
                //                    ex.StackTrace.Substring(ex.StackTrace.LastIndexOf(":line") + 5) + ex.Message.ToString(), "Ding", (new StackTrace()).GetFrame(0).GetMethod().Name, ex, false, Level.BelowHigh);
                str_Array = new string[] { "", ex.StackTrace.Substring(ex.StackTrace.LastIndexOf(":line") + 5) + ex.Message.ToString(), "", "", "" };
            }

            return str_Array;
        }

        [WebMethod(Description = "GetBalance for ding")]
        public string[] GetBalance(string Seq, string Username, string PassWd, ref Eztop.GetBalanceResponse _GetBalanceResponse)
        {
            string[] str_Array = new string[5];
            try
            {
                Eztop.EDTSManager _EDTSManager = new Eztop.EDTSManager();
                Eztop.GetBalanceRequest _GetBalanceRequest = new Eztop.GetBalanceRequest()
                {
                    MessageID = Convert.ToInt32(Seq),
                    AuthenticationToken = new Eztop.AuthenticationToken()
                    {
                        AuthenticationID = Username,
                        AuthenticationPassword = PassWd,
                    }
                };
                _GetBalanceResponse = _EDTSManager.GetBalance(_GetBalanceRequest);

                str_Array = new string[] { "SUCCESS", "", "", "", "" };
            }
            catch (Exception ex)
            {
                //Logging.StoreLog(strTerminal, Seq, StoreType.Xml,
                //                    LogType.X, pAppType, "",
                //                    ex.StackTrace.Substring(ex.StackTrace.LastIndexOf(":line") + 5) + ex.Message.ToString(), "Ding", (new StackTrace()).GetFrame(0).GetMethod().Name, ex, false, Level.BelowHigh);
                str_Array = new string[] { "", ex.StackTrace.Substring(ex.StackTrace.LastIndexOf(":line") + 5) + ex.Message.ToString(), "", "", "" };
            }

            return str_Array;
        }

        [WebMethod(Description = "GetTargetTopUpAmount for ding")]
        public string[] GetTargetTopUpAmount(string Seq, string Username, string PassWd, string CountryCode, string OperatorCode, double dbAmount, ref  Eztop.GetTargetTopUpAmountResponse _GetTargetTopUpAmountResponse)
        {
            string[] str_Array = new string[5];
            try
            {
                Eztop.EDTSManager _EDTSManager = new Eztop.EDTSManager();
                Eztop.GetTargetTopUpAmountRequest _GetTargetTopUpAmountRequest = new Eztop.GetTargetTopUpAmountRequest()
                {
                    MessageID = Convert.ToInt32(Seq),
                    AuthenticationToken = new Eztop.AuthenticationToken()
                    {
                        AuthenticationID = Username,
                        AuthenticationPassword = PassWd
                    },

                    OperatorCode = OperatorCode,
                    CountryCode = CountryCode,
                    Amount = dbAmount
                };
                _GetTargetTopUpAmountResponse = _EDTSManager.GetTargetTopUpAmount(_GetTargetTopUpAmountRequest);

                str_Array = new string[] { "SUCCESS", "", "", "", "" };
            }
            catch (Exception ex)
            {
                //Logging.StoreLog(strTerminal, Seq, StoreType.Xml,
                //                    LogType.X, pAppType, "",
                //                    ex.StackTrace.Substring(ex.StackTrace.LastIndexOf(":line") + 5) + ex.Message.ToString(), "Ding", (new StackTrace()).GetFrame(0).GetMethod().Name, ex, false, Level.BelowHigh);
                str_Array = new string[] { "", ex.StackTrace.Substring(ex.StackTrace.LastIndexOf(":line") + 5) + ex.Message.ToString(), "", "", "" };
            }

            return str_Array;
        }

        [WebMethod(Description = "GetTopupTransactionStatus for ding")]
        public string[] GetTopupTransactionStatus(string Seq, string Username, string PassWd, string strPhoneNumber, ref Eztop.GetTopUpTransactionStatusResponse _GetTopUpTransactionStatusResponse)
        {
            string[] str_Array = new string[5];
            try
            {
                Eztop.EDTSManager _EDTSManager = new Eztop.EDTSManager();
                Eztop.GetTopUpTransactionStatusRequest _GetTopUpTransactionStatusRequest = new Eztop.GetTopUpTransactionStatusRequest()
                {
                    MessageID = Convert.ToInt32(Seq),
                    AuthenticationToken = new Eztop.AuthenticationToken()
                    {
                        AuthenticationID = Username,
                        AuthenticationPassword = PassWd,
                    },
                    PhoneNumber = strPhoneNumber
                };
                _GetTopUpTransactionStatusResponse = _EDTSManager.GetTopUpTransactionStatus(_GetTopUpTransactionStatusRequest);

                str_Array = new string[] { "SUCCESS", "", "", "", "" };
            }
            catch (Exception ex)
            {
                //Logging.StoreLog(strTerminal, Seq, StoreType.Xml,
                //                    LogType.X, pAppType, "",
                //                    ex.StackTrace.Substring(ex.StackTrace.LastIndexOf(":line") + 5) + ex.Message.ToString(), "Ding", (new StackTrace()).GetFrame(0).GetMethod().Name, ex, false, Level.BelowHigh);
                str_Array = new string[] { "", ex.StackTrace.Substring(ex.StackTrace.LastIndexOf(":line") + 5) + ex.Message.ToString(), "", "", "" };
            }

            return str_Array;
        }

        [WebMethod(Description = "TopUpPhoneAccount for ding")]
        public string[] TopUpPhoneAccount(string Seq, string Username, string PassWd, string CountryIso, string CountryCode, string OperatorCode, string PhoneNumber, string Amount, ref Eztop.TopUpPhoneAccountResponse _TopUpPhoneAccountResponse)
        {
            string[] str_Array = new string[5];
            try
            {
                Eztop.EDTSManager _EDTSManager = new Eztop.EDTSManager();
                Eztop.TopUpPhoneAccountRequest _TopUpPhoneAccountRequest = new Eztop.TopUpPhoneAccountRequest()
                {
                    MessageID = Convert.ToInt32(Seq),
                    AuthenticationToken = new Eztop.AuthenticationToken()
                    {
                        AuthenticationID = Username,
                        AuthenticationPassword = PassWd
                    },

                    CountryCode = CountryCode,
                    OperatorCode = OperatorCode,
                    PhoneNumber = PhoneNumber,
                    Amount = Convert.ToDouble(Amount)
                };
                _TopUpPhoneAccountResponse = _EDTSManager.TopUpPhoneAccount(_TopUpPhoneAccountRequest);

                str_Array = new string[] { "SUCCESS", "", "", "", "" };
            }
            catch (Exception ex)
            {
                //Logging.StoreLog(strTerminal, Seq, StoreType.Xml,
                //                    LogType.X, pAppType, "",
                //                    ex.StackTrace.Substring(ex.StackTrace.LastIndexOf(":line") + 5) + ex.Message.ToString(), "Ding", (new StackTrace()).GetFrame(0).GetMethod().Name, ex, false, Level.BelowHigh);
                str_Array = new string[] { "", ex.StackTrace.Substring(ex.StackTrace.LastIndexOf(":line") + 5) + ex.Message.ToString(), "", "", "" };
            }

            return str_Array;
        }

        [WebMethod(Description = "_GetTopUpTransactionStatusResponse for ding")]
        public string[] _GetTopUpTransactionStatusResponse(string Seq, string Username, string PassWd, string PhoneNo, ref  Eztop.GetTopUpTransactionStatusResponse _GetTopUpTransactionStatusResponse)
        {
            string[] str_Array = new string[5];
            try
            {
                Eztop.EDTSManager _EDTSManager = new Eztop.EDTSManager();
                Eztop.GetTopUpTransactionStatusRequest _GetTopUpTransactionStatusRequest = new Eztop.GetTopUpTransactionStatusRequest()
                {
                    MessageID = Convert.ToInt32(Seq),
                    AuthenticationToken = new Eztop.AuthenticationToken()
                    {
                        AuthenticationID = Username,
                        AuthenticationPassword = PassWd,
                    },
                    PhoneNumber = PhoneNo
                };
                _GetTopUpTransactionStatusResponse = _EDTSManager.GetTopUpTransactionStatus(_GetTopUpTransactionStatusRequest);
                str_Array = new string[] { "SUCCESS", "", "", "", "" };
            }
            catch (Exception ex)
            {
                //Logging.StoreLog(strTerminal, Seq, StoreType.Xml,
                //                    LogType.X, pAppType, "",
                //                    ex.StackTrace.Substring(ex.StackTrace.LastIndexOf(":line") + 5) + ex.Message.ToString(), "Ding", (new StackTrace()).GetFrame(0).GetMethod().Name, ex, false, Level.BelowHigh);
                str_Array = new string[] { "", ex.StackTrace.Substring(ex.StackTrace.LastIndexOf(":line") + 5) + ex.Message.ToString(), "", "", "" };
            }

            return str_Array;
        }

        [WebMethod(Description = "Send Request For Star AIR")]
        public string[] SendRequestForStarAir(string strRequestXml, string strSequenceNo, string Stock, string strReqSoapAction, string strRequestURL, ref string strWebCookie, ref string strResponse)
        {
            string[] rstr_ParseResult = new string[4];
            try
            {
                string Error = "";

                string cert_Path = System.Web.HttpContext.Current.Server.MapPath("~/Certificates\\StarAirCert.pfx"); //Path.Combine(HttpRuntime.AppDomainAppPath, "Certificate\\Cert.pfx");//ConfigurationManager.AppSettings["cert_Path"].ToString();
                string cert_Password = "Hassan";
                Stream strmRequestStream = null;

                int i = 1;
            OUT:
                HttpWebRequest httpwebRequest = (HttpWebRequest)HttpWebRequest.Create(strRequestURL);
                httpwebRequest.Credentials = CredentialCache.DefaultNetworkCredentials;
                httpwebRequest.Proxy = null;
                httpwebRequest.KeepAlive = false;
                X509Certificate2 cert = new X509Certificate2(cert_Path, cert_Password);
                httpwebRequest.ClientCertificates.Add(cert);
                httpwebRequest.ProtocolVersion = HttpVersion.Version10;
                httpwebRequest.ServicePoint.ConnectionLimit = 1;
                httpwebRequest.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
                httpwebRequest.Method = "POST";
                httpwebRequest.ContentType = "text/xml; charset=utf-8";
                httpwebRequest.Headers.Add("SOAPAction", strReqSoapAction);
                httpwebRequest.Accept = "text/xml";
                httpwebRequest.Timeout = 300000;
                //strRequestXml = GetSoapEnvelope(strRequestXml, hshCredential);
                byte[] queryByte = Convertbyte(strSequenceNo, strRequestXml.ToString(), Encoding.UTF8.GetEncoder());
                httpwebRequest.ContentLength = queryByte.Length;

                #region Write Request

                try
                {
                    strmRequestStream = httpwebRequest.GetRequestStream();
                }
                catch (Exception ex)
                {
                    if (i == 1)
                    {
                        i++;
                        goto OUT;
                    }

                    if (ex.InnerException != null)
                    {
                        Error = ex.InnerException.Message;
                        rstr_ParseResult = new string[] { "", ex.ToString(), "SendRequestForStarAir" + "Level-1", "" };
                        //return false;
                    }
                    Error = ex.Message.ToString();
                    rstr_ParseResult = new string[] { "", ex.ToString(), "SendRequestForStarAir" + "Level-1", "" };
                    //return false;
                }
                strmRequestStream.Write(queryByte, 0, queryByte.Length);
                #endregion

                HttpWebResponse webResponse = null;
                try
                {
                    webResponse = (HttpWebResponse)httpwebRequest.GetResponse();
                }
                catch (Exception e)
                {
                    FieldInfo fieldInformation = httpwebRequest.GetType().GetField("_HttpResponse", BindingFlags.NonPublic | BindingFlags.Instance);
                    if (fieldInformation != null)
                    {
                        webResponse = (HttpWebResponse)fieldInformation.GetValue(httpwebRequest);
                    }
                    if (webResponse == null)
                    {
                        strmRequestStream.Close();
                        if (e.InnerException != null)
                        {
                            Error = e.InnerException.Message;
                            rstr_ParseResult = new string[] { "", e.ToString(), "SendRequestForStarAir" + "Level-1", "" };
                            //return false;
                        }
                        Error = e.Message;
                        //return false;
                        rstr_ParseResult = new string[] { "", e.ToString(), "SendRequestForStarAir" + "Level-1", "" };
                    }
                }

                Stream strmResponseStream = strmResponseStream = webResponse.GetResponseStream();
                if (webResponse.ContentEncoding.ToLower().Contains("gzip"))
                {
                    strmResponseStream = new GZipStream(strmResponseStream, CompressionMode.Decompress);
                }
                else if (webResponse.ContentEncoding.ToLower().Contains("deflate"))
                {
                    strmResponseStream = new DeflateStream(strmResponseStream, CompressionMode.Decompress);
                }
                StreamReader strmReader = new StreamReader(strmResponseStream, Encoding.Default);
                strResponse = strmReader.ReadToEnd();
                strmReader.Close();
                strmRequestStream.Close();
                strmResponseStream.Close();
                rstr_ParseResult = new string[] { strResponse, "", "SendRequestForStarAir" + "Level0", "" };
                return rstr_ParseResult;

            }
            catch (Exception ex)
            {
                string strLineNo = string.Empty;
                if (ex.StackTrace != null)
                {
                    if (ex.StackTrace.Contains("cs:line"))
                    {
                        strLineNo = ex.StackTrace.Substring(ex.StackTrace.IndexOf("cs:line"));
                    }
                }
                strResponse = "Unable to connect " + Stock.ToString() + " Server";
                return rstr_ParseResult = new string[] { "", ex.ToString(), "SendRequestForStarAir" + "Level-1", "" };
            }
        }

        [WebMethod(Description = "Send Request For Star AIR(New), NepalAir, Hermes and for Rest Support")]
        public bool SendRequestForRestClient(string strRequest, string strSequenceNo, string Stock, string strMethod, string strUserAgent, string strRequestURL, ref string strResponse, ref string Error)
        {

            try
            {
                var client = new RestClient(strRequestURL);
                client.Timeout = -1;
                var request = strMethod.ToUpper() == "GET" ? new RestRequest(Method.GET) : strMethod.ToUpper() == "PUT" ? new RestRequest(Method.PUT) : strMethod.ToUpper() == "DELETE" ? new RestRequest(Method.DELETE) : new RestRequest(Method.POST);
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
                //if (strUserAgent != "")
                //    request.AddHeader("User-Agent", strUserAgent);
                if (strUserAgent != "")
                    client.UserAgent = strUserAgent;
                try
                {
                    IRestResponse response1 = client.Execute(request);
                    strResponse = response1.Content.ToString();
                    if (string.IsNullOrEmpty(strResponse))
                    {
                        Error = response1.ErrorMessage;
                        return false;

                    }
                }
                catch (Exception ex)
                {
                    Error = ex.Message.ToString();
                    return false;
                }
                return true;
            }
            catch (Exception ex)
            {
                string strLineNo = string.Empty;
                if (ex.StackTrace != null)
                {
                    if (ex.StackTrace.Contains("cs:line"))
                    {
                        strLineNo = ex.StackTrace.Substring(ex.StackTrace.IndexOf("cs:line"));
                    }
                }
                Error = "EX:- Unable to connect " + Stock.ToString() + " Server";
                return false;
            }
        }

        [WebMethod(Description = "Send Request For AirAsia India")]
        public bool SendRequestForRestAsPostman(string strRequest, string strSequenceNo, string Stock, string strMethod, string strUserAgent, string strRequestURL, ref string strResponse, ref string Error)
        {

            try
            {
                var client = new RestClient(strRequestURL);
                client.Timeout = -1;
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
                var request = strMethod.ToUpper() == "GET" ? new RestRequest(Method.GET) : strMethod.ToUpper() == "PUT" ? new RestRequest(Method.PUT) : strMethod.ToUpper() == "DELETE" ? new RestRequest(Method.DELETE) : new RestRequest(Method.POST);
                request.AddHeader("Content-Type", "application/json");
                request.AddParameter("application/json", strRequest, ParameterType.RequestBody);
                try
                {
                    IRestResponse response = client.Execute(request);
                    strResponse = response.Content.ToString();
                    if (string.IsNullOrEmpty(strResponse))
                    {
                        Error = response.ErrorMessage;
                        return false;
                    }
                }
                catch (Exception ex)
                {
                    
                    Error = ex.Message.ToString();
                    return false;
                }
                return true;
            }
            catch (Exception ex)
            {
                string strLineNo = string.Empty;
                if (ex.StackTrace != null)
                {
                    if (ex.StackTrace.Contains("cs:line"))
                    {
                        strLineNo = ex.StackTrace.Substring(ex.StackTrace.IndexOf("cs:line"));
                    }
                }
                Error = "EX:- Unable to connect " + Stock.ToString() + " Server";
                return false;
            }
        }
    }
    public class MyWebClient : WebClient
    {
        protected override WebRequest GetWebRequest(Uri address)
        {
            HttpWebRequest request = base.GetWebRequest(address) as HttpWebRequest;
            request.AutomaticDecompression = DecompressionMethods.Deflate | DecompressionMethods.GZip;
            return request;
        }

    }
}
