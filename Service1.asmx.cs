using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;
using System.Web.Services;

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
    public class Service1 : System.Web.Services.WebService
    {

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

        [WebMethod]
        public string SendRequest(string strUrl, string strMethod, string strSoapAction, string strRequestData)
        {
            string strResponse = string.Empty;
            try
            {
                if (strRequestData.Contains("AddPaymentToBookingRequest"))
                {
                    strRequestData = strRequestData.Replace("<Installments>1</Installments>", "<Installments>0</Installments>");
                }

                HttpWebRequest httpwebRequest = (HttpWebRequest)HttpWebRequest.Create(strUrl);
                httpwebRequest.Credentials = CredentialCache.DefaultNetworkCredentials;
                httpwebRequest.Proxy = null;
                httpwebRequest.KeepAlive = false;
                httpwebRequest.ProtocolVersion = HttpVersion.Version10;
                httpwebRequest.ServicePoint.ConnectionLimit = 1;
                httpwebRequest.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
                httpwebRequest.Method = strMethod;
                httpwebRequest.ContentType = "text/xml; charset=utf-8";
                httpwebRequest.Headers.Add("SOAPAction", strSoapAction);
                httpwebRequest.Accept = "text/xml";
                byte[] queryByte = Convertbyte(strRequestData, Encoding.UTF8.GetEncoder());
                byte[] strbyte = System.Text.Encoding.UTF8.GetBytes(strRequestData);
                httpwebRequest.ContentLength = queryByte.Length;

                Stream strmRequestStream;
                try
                {
                    strmRequestStream = httpwebRequest.GetRequestStream();
                }
                catch (Exception ex)
                {
                    if (ex.InnerException != null)
                    {
                        //strError = ex.InnerException.Message;
                        //return false;
                        return strResponse;
                    }
                    return strResponse;
                }
                strmRequestStream.Write(queryByte, 0, queryByte.Length);

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
                            //strError = e.InnerException.Message;
                            //return false;
                            return strResponse;
                        }
                        //strError = e.Message;
                        //return false;
                        return strResponse;
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
               
            }
            catch (Exception ex)
            {
                //rstr_ParseResult = new string[] { "", ex.ToString(), "SendRequestForRadixxNavitare" + "Level-1", "" };
                //return rstr_ParseResult;
            }
            return strResponse;
        }
        
        private CookieContainer cookiecontainer;
        [WebMethod(Description = "SendRequestWithHttp")]
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
                    // IP_HELP.PatchIPHelp _iip = new IP_HELP.PatchIPHelp(); 
                    //IPHELP.PatchIPHelp _ip = new IPHELP.PatchIPHelp();


                    //_ip.Url = ip;

                    //str_Array = _ip.se .SendRequestWithHttp(URL, sessionid, method, parameter);
                    //return str_Array;

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

    }
}
