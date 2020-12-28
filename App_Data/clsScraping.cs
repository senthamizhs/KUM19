using System;
using System.Data;
using System.Configuration;
using System.Linq;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.HtmlControls;
using System.Web.UI.WebControls;
using System.Web.UI.WebControls.WebParts;
using System.Xml.Linq;
using System.Collections;
using System.Net;
using System.Text;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.IO.Compression;
using System.Collections.Generic;
using System.Reflection;
using System.Globalization;
using System.Net.Security;
using IPHelp;

public class clsScraping
{
    private CookieContainer cookiecontainer;
    private string _strPath;
    public clsScraping()
    {
        _strPath = ConfigurationManager.AppSettings["FolderLog"].ToString();
    }

    #region WebRequsts & Response
    public string[] GetResponseWebReqWSWG(string pstrAgentId, string pstrTerminalId, string pstrSequenceNo, string pstrSiteName, 
                                          string pstrRequestUrl, string pstrAccessMethod,string pstrCookies,
                                          string pstrPostParameters, string pstrFunctionName, string pstrCertificateName, int pintTimeout)
    {
        string[] rstr_ParseResult = new string[5];
        try
        {
            string strWebResponse = "";
            string strWebError = "";
            string strWebCookie = "";

            string strCertificatePath = _strPath + "Certificates\\";
            strWebResponse = strWebCookie = strWebError = string.Empty;

            X509Certificate Cert = X509Certificate.CreateFromCertFile(strCertificatePath + pstrCertificateName);
            ServicePointManager.ServerCertificateValidationCallback += new RemoteCertificateValidationCallback(ValidateRemoteCertificate);


            HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(pstrRequestUrl);
            httpWebRequest.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
            httpWebRequest.ContentType = "application/x-www-form-urlencoded";
            httpWebRequest.CookieContainer = cookiecontainer;
            
            httpWebRequest.UserAgent = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.2.13) Gecko/20101203 Firefox/5.0";
            httpWebRequest.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,application/json, text/javascript,*/*;q=0.8";
            httpWebRequest.ClientCertificates.Add(Cert);
            httpWebRequest.Credentials = CredentialCache.DefaultCredentials;
            httpWebRequest.Method = pstrAccessMethod;
            if (pstrFunctionName.Contains("6EAgentHome"))
            {
                httpWebRequest.AllowAutoRedirect = true;
                httpWebRequest.Referer = "https://book.goindigo.in";
            }
            httpWebRequest.Timeout = pintTimeout;
            string strCookie = pstrCookies;
            if (!string.IsNullOrEmpty(strCookie))
            {
                httpWebRequest.Headers["Cookie"] = strCookie.TrimEnd(';');
            }

            byte[] bytarrParam = Encoding.ASCII.GetBytes(pstrPostParameters);
            Stream strmInput = null;
            if (pstrAccessMethod.Contains("POST"))
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
                strmrdrResponse.Close();
            }
            strWebResponse = strHtmlResponse;
            rstr_ParseResult = new string[] { strWebResponse, "", "GetResponseWebReqWSWG" + "Level0", strWebCookie, strWebError };
            return rstr_ParseResult;
        }
        catch (Exception ex)
        {
            rstr_ParseResult = new string[] { "", ex.Message, "GetResponseWebReqWSWG" + "Level-1", "", "" };
            return rstr_ParseResult;
        }
    }
    //webrequest (Gzip, No ssl )
    public string[] GetResponseWebReqWoSWG(string pstrAgentId, string pstrTerminalId, string pstrSequenceNo, 
                                           string pstrSiteName, string pstrRequestUrl, string pstrAccessMethod,
                                           string pstrCookie, string pstrParameters, string pstrFunctionName, int pintTimeout)
    {
        string[] rstr_ParseResult = new string[5];
        try
        {
            string strWebResponse = "";
            string strWebCookie = "";

            strWebResponse = string.Empty;
            strWebCookie = string.Empty;
            

            HttpWebRequest HttpReq = (HttpWebRequest)WebRequest.Create(pstrRequestUrl);

            HttpReq.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
            HttpReq.Timeout = pintTimeout;
            HttpReq.ContentType = "application/x-www-form-urlencoded";
            HttpReq.UserAgent = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.2.13) Gecko/20101203 Firefox/3.6.13";
            
            if (!string.IsNullOrEmpty(pstrCookie))
            {
                HttpReq.Headers["Cookie"] = pstrCookie.TrimEnd(';');
            }

            if (!string.IsNullOrEmpty(pstrParameters))
            {
                HttpReq.Method = "POST";
                byte[] lbPostBuffer = Encoding.Default.GetBytes(pstrParameters);

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
            rstr_ParseResult = new string[] { strWebResponse, "", "GetResponseWebReqWoSWG" + "Level0", strWebCookie, "" };
            return rstr_ParseResult;
        }
        catch (Exception ex)
        {
            rstr_ParseResult = new string[] { "", ex.Message, "GetResponseWebReqWoSWG" + "Level0", "", "" };
            return rstr_ParseResult;
        }
    }
    //WebRequest (Gzip, SSL)
    public string[] GetResponseWebReqWSWG(string pstrAgentId, string pstrTerminalId, string pstrSequenceNo, 
                                          string pstrSiteName, string pstrRequestUrl, string pstrAccessMethod, 
                                          string pstrCookie,string pstrParameters, string pstrFunctionName,
                                          string pstrCertificateName, string pstrReferenceUrl, int pintTimeout)
    {
        string[] rstr_ParseResult = new string[5];
        string strhtmlResponse = string.Empty;
        try
        {
            byte[] bytes;
            string strWebResponse = "";
            string strWebCookie = "";
            HttpWebResponse webResponse;


            string strCertificatePath = _strPath + "Certificates\\";

            X509Certificate Cert = X509Certificate.CreateFromCertFile(strCertificatePath + pstrCertificateName);
            ServicePointManager.ServerCertificateValidationCallback += new RemoteCertificateValidationCallback(ValidateRemoteCertificate);
            
         

            HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create(pstrRequestUrl);
            webRequest.Timeout = pintTimeout;
            webRequest.Method = pstrAccessMethod;
            webRequest.CookieContainer = cookiecontainer;
            webRequest.ContentType = "application/json;";
            webRequest.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,application/json, text/javascript,*/*;q=0.8";
            webRequest.UserAgent = "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.874.121 Safari/535.2";
            webRequest.Headers.Add("Accept-Language", "en-us");
            webRequest.Headers.Add("Accept-Encoding", "gzip, deflate");
            webRequest.Headers.Add("Cache-Control", "no-cache");
            webRequest.Credentials = CredentialCache.DefaultCredentials;

            if (!string.IsNullOrEmpty(pstrCookie))
                webRequest.Headers["Cookie"] = pstrCookie.TrimEnd(';');

            if (!string.IsNullOrEmpty(pstrReferenceUrl))
                webRequest.Referer = pstrReferenceUrl;

            if (pstrRequestUrl.Contains("https"))
                webRequest.ClientCertificates.Add(Cert);

            Stream os = null;
            bytes = Encoding.ASCII.GetBytes(pstrParameters);
            if (pstrAccessMethod.Contains("POST"))
            {
                webRequest.ContentLength = bytes.Length;   //Count bytes to send
                os = webRequest.GetRequestStream();
                os.Write(bytes, 0, bytes.Length);
            }//Send it
            webResponse = (HttpWebResponse)webRequest.GetResponse();
            Stream responsestream = webResponse.GetResponseStream();

            if (webResponse.ContentEncoding.ToLower().Contains("gzip"))
            {
                responsestream = new GZipStream(responsestream, CompressionMode.Decompress);
            }
            else if (webResponse.ContentEncoding.ToLower().Contains("deflate"))
            {
                responsestream = new DeflateStream(responsestream, CompressionMode.Decompress);
            }
            if (webResponse.Headers[HttpResponseHeader.SetCookie] != null)
            {
                for (int i = 0; i < webResponse.Headers.Count; i++)
                {
                    if (webResponse.Headers.GetKey(i).Contains("Set-Cookie"))
                    {
                        strWebCookie += webResponse.Headers[i] + "`";
                    }
                }
            }
            strWebCookie = strWebCookie.TrimEnd('`');
            StreamReader srResponse;
            using (srResponse = new StreamReader(responsestream))
            {
                strhtmlResponse = srResponse.ReadToEnd();
                // Close and clean up the StreamReader
                srResponse.Close();
            }
            strWebResponse = strhtmlResponse;

            rstr_ParseResult = new string[] { strWebResponse, "", "GetResponseWebReqWSWG" + "Level0", strWebCookie, "" };
            return rstr_ParseResult;
        }
        catch (Exception ex)
        {
            rstr_ParseResult = new string[] { "", ex.Message, "GetResponseWebReqWSWG" + "Level-1", "", "" };
            return rstr_ParseResult;
        }
    }
    //image (Gzip, ssl)
    public string[] GetResponseWebReqWSWG(string pstrAgentId, string pstrTerminalId, string pstrSequenceNo, string pstrSiteName, 
                                          string pstrRequestUrl, string pstrAccessMethod, string pstrParameters,
                                          string pstrFunctionName, string pstrCertificateName, int pintTimeout)
    {
        string strhtmlResponse = string.Empty;
        string CerPath = string.Empty;
        string[] rstr_ParseResult = new string[5];
        try
        {
            string pstrWebCookie = string.Empty; string pstrWebError = string.Empty;
            byte[] bytes;
            byte[] bytres;
            byte[] bytarrResult = null;

            pstrWebCookie = string.Empty;
            pstrWebError = string.Empty;

            HttpWebResponse webResponse;

            CerPath = _strPath + "Certificates\\";
            //CerPath = System.Web.HttpContext.Current.Server.MapPath("~/Certificates\\");

            X509Certificate Cert = X509Certificate.CreateFromCertFile(CerPath + pstrCertificateName);

            HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create(pstrRequestUrl);
            webRequest.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip,deflate");
            webRequest.Method = pstrAccessMethod;

            webRequest.ContentType = "application/x-www-form-urlencoded";
            webRequest.Referer = pstrRequestUrl;
            webRequest.UserAgent = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.2.13) Gecko/20101203 Firefox/5.0";
            webRequest.ClientCertificates.Add(Cert);
            webRequest.Credentials = CredentialCache.DefaultCredentials;
            webRequest.Timeout = pintTimeout;

            bytes = Encoding.ASCII.GetBytes(pstrParameters);
            Stream os = null;
            if (pstrAccessMethod.Contains("POST"))
            {
                webRequest.ContentLength = bytes.Length;   //Count bytes to send
                os = webRequest.GetRequestStream();
                os.Write(bytes, 0, bytes.Length);
            }//Send it
            webResponse = (HttpWebResponse)webRequest.GetResponse();
            Stream responsestream = webResponse.GetResponseStream();


            if (webResponse.ContentEncoding.ToLower().Contains("gzip"))
            {
                responsestream = new GZipStream(responsestream, CompressionMode.Decompress);
            }
            else if (webResponse.ContentEncoding.ToLower().Contains("deflate"))
            {
                responsestream = new DeflateStream(responsestream, CompressionMode.Decompress);
            }
            bytres = ReadFully(responsestream);
            if (webResponse.Headers[HttpResponseHeader.SetCookie] != null)
            {
                pstrWebCookie = webResponse.Headers[HttpResponseHeader.SetCookie];
            }

            bytarrResult = bytres;

            rstr_ParseResult = new string[] { ASCIIEncoding.ASCII.GetString(bytarrResult), "", "GetResponseWebReqWSWG" + "Level0", pstrWebCookie, "" };
            return rstr_ParseResult;
        }
        catch (Exception ex)
        {
            rstr_ParseResult = new string[] { "", ex.ToString(), "GetResponseWebReqWSWG" + "Level0", "", "" };
            return rstr_ParseResult;
        }
    }
    //image (Gzip, No ssl)
    public string[] GetResponseWebClientWoSWG(string pstrAgentId, string pstrTerminalId, string pstrSequenceNo, string pstrSiteName,
                                           string pstrRequestUrl, string pstrAccessMethod, string pstrCookie,
                                           string pstrParameters, string pstrFunctionName, int pintTimeout)
    {
        string strResponse = string.Empty;
        string[] rstr_ParseResult = new string[5];
        try
        {
            byte[] bytarrResult = null; string pstrWebCookie = ""; 
            MyWebClient webclient = new MyWebClient();
            byte[] bytResponse = new byte[] { };
            //webclient.Headers.Add("Content-Type", "application/x-www-form-urlencoded");
            webclient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.2.13) Gecko/20101203 Firefox/3.6.13");
            webclient.Headers.Add("Accept-Encoding", "gzip");
            webclient.Headers.Add("Timeout", pintTimeout.ToString());

           
            if (pstrAccessMethod == "GET")
            {
                bytResponse = webclient.DownloadData(pstrRequestUrl);
            }
            else if (pstrAccessMethod == "POST")
            {
                bytResponse = webclient.UploadData(pstrRequestUrl, "POST", Encoding.ASCII.GetBytes(pstrParameters));
            }

            for (int i = 0; i < webclient.ResponseHeaders.Count; i++)
            {
                if (webclient.ResponseHeaders.AllKeys[i].ToString().Contains("Set-Cookie"))
                {
                    if (!string.IsNullOrEmpty(webclient.ResponseHeaders[HttpResponseHeader.SetCookie].ToString()))
                    {
                        pstrWebCookie = webclient.ResponseHeaders[HttpResponseHeader.SetCookie].ToString();
                        break;
                    }
                }
            }
            bytarrResult = bytResponse;
            rstr_ParseResult = new string[] { ASCIIEncoding.ASCII.GetString(bytarrResult), "", "GetResponseWebClientWoSWG" + "Level0", "", "" };
            return rstr_ParseResult;
        }
        catch (Exception ex)
        {
            rstr_ParseResult = new string[] { "", ex.ToString(), "GetResponseWebClientWoSWG" + "Level-1", "", "" };
            return rstr_ParseResult;
        }
    }
    //ForAirarbia
    public string[] GetResponseWebReqWISWGR(string pstrAgentId, string pstrTerminalId, string pstrSequenceNo, string pstrSiteName,
                                            string pstrRequestUrl, string pstrAccessMethod, 
                                            string pstrParameters, Hashtable hshHeaders, string strFunctionName, 
                                             string strCertificateName, string strRefUrl, int pintTimeout)
    {
        string strhtmlResponse = string.Empty;
        string[] rstr_ParseResult = new string[5];
        try
        {
            byte[] bytes;
            string strWebResponse = string.Empty;
            string strWebCookie = string.Empty;

            HttpWebResponse webResponse;

            string CerPath = _strPath + "Certificates\\";
            X509Certificate Cert = X509Certificate.CreateFromCertFile(CerPath + strCertificateName);
            ServicePointManager.ServerCertificateValidationCallback += new RemoteCertificateValidationCallback(ValidateRemoteCertificate);
            string strCookie = string.Empty;
            foreach (DictionaryEntry hshvalue in hshHeaders)
            {
                strCookie += hshvalue.Key.ToString() + "=" + hshvalue.Value.ToString() + ";";
            }

            HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create(pstrRequestUrl);
            webRequest.Timeout = pintTimeout;
            webRequest.Method = pstrAccessMethod;
            webRequest.CookieContainer = cookiecontainer;
            Stream os = null;
            bytes = Encoding.ASCII.GetBytes(pstrParameters);

            webRequest.ContentType = "application/x-www-form-urlencoded";

            if (!string.IsNullOrEmpty(strCookie))
            {
                webRequest.Headers["Cookie"] = strCookie.TrimEnd(';');
            }

            webRequest.Referer = strRefUrl;
            webRequest.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,application/json, text/javascript,*/*;q=0.8";
            webRequest.UserAgent = "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.874.121 Safari/535.2";
            webRequest.Headers.Add("Accept-Language", "en-us");
            webRequest.Headers.Add("Accept-Encoding", "gzip, deflate");
            webRequest.Headers.Add("Cache-Control", "no-cache");
            if (pstrRequestUrl.Contains("https"))
            {
                webRequest.ClientCertificates.Add(Cert);
            }

            webRequest.Credentials = CredentialCache.DefaultCredentials;

            if (pstrAccessMethod.Contains("POST"))
            {
                webRequest.ContentLength = bytes.Length;   //Count bytes to send
                os = webRequest.GetRequestStream();
                os.Write(bytes, 0, bytes.Length);
            }//Send it
            webResponse = (HttpWebResponse)webRequest.GetResponse();
            Stream responsestream = webResponse.GetResponseStream();

            if (webResponse.ContentEncoding.ToLower().Contains("gzip"))
            {
                responsestream = new GZipStream(responsestream, CompressionMode.Decompress);
            }
            else if (webResponse.ContentEncoding.ToLower().Contains("deflate"))
            {
                responsestream = new DeflateStream(responsestream, CompressionMode.Decompress);
            }
            if (webResponse.Headers[HttpResponseHeader.SetCookie] != null)
            {
                for (int i = 0; i < webResponse.Headers.Count; i++)
                {
                    if (webResponse.Headers.GetKey(i).Contains("Set-Cookie"))
                    {
                        strWebCookie += webResponse.Headers[i] + "`";
                    }
                }
            }
            strWebCookie = strWebCookie.TrimEnd('`');
            StreamReader srResponse;
            using (srResponse = new StreamReader(responsestream))
            {
                strhtmlResponse = srResponse.ReadToEnd();
                // Close and clean up the StreamReader
                srResponse.Close();
            }
            strWebResponse = strhtmlResponse;

            rstr_ParseResult = new string[] { strWebResponse, "", "GetResponseWebReqWISWGR" + "Level0", "", "" };
            return rstr_ParseResult;
        }
        catch (Exception ex)
        {
            rstr_ParseResult = new string[] { "", ex.ToString(), "GetResponseWebReqWISWGR" + "Level-1", "", "" };
            return rstr_ParseResult;
        }
    }
    //SmartWebClient
    public string[] GetResponsesmartWebClientWoSWG(string pstrAgentId, string pstrTerminalId, string pstrSequenceNo,
                                                   string pstrSiteName, string pstrRequestUrl, string pstrAccessMethod,
                                                   string pstrParameters, string pstrFunctionName, string pstrCookie, int pintTimeout)
    {
        string strResult = string.Empty;
        string[] rstr_ParseResult = new string[5];
        try
        {
            SmartWebClient.Smart_WebClient webclient = new SmartWebClient.Smart_WebClient();
            byte[] bytResponse;

            string strWebResponse = string.Empty;
            string strWebCookie = string.Empty;
            string strWebError = string.Empty;

            webclient.Headers.Add("Content-Type", "application/x-www-form-urlencoded");
            webclient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.2.13) Gecko/20101203 Firefox/3.6.13");
            webclient.Headers.Add("Accept-Encoding", "gzip");
            webclient.Headers.Add("Timeout", pintTimeout.ToString());


            webclient.Headers[HttpRequestHeader.Cookie] = pstrCookie.TrimEnd(';');


            if (pstrAccessMethod == "GET")
            {
                bytResponse = webclient.DownloadData(pstrRequestUrl);
                strResult = Encoding.ASCII.GetString(bytResponse);
            }
            else if (pstrAccessMethod == "POST")
            {
                bytResponse = webclient.UploadData(pstrRequestUrl, "POST", Encoding.ASCII.GetBytes(pstrParameters));
                strResult = Encoding.ASCII.GetString(bytResponse);
            }
            for (int i = 0; i < webclient.ResponseHeaders.Count; i++)
            {
                if (webclient.ResponseHeaders.AllKeys[i].ToString().Contains("Set-Cookie"))
                {
                    if (!string.IsNullOrEmpty(webclient.ResponseHeaders[HttpResponseHeader.SetCookie].ToString()))
                    {
                        strWebCookie = webclient.ResponseHeaders[HttpResponseHeader.SetCookie].ToString();
                        break;
                    }
                }
            }
            strWebResponse = strResult;
            rstr_ParseResult = new string[] { strWebResponse, "", "GetResponsesmartWebClientWoSWG" + "Level0", "", "" };
            return rstr_ParseResult;
        }
        catch (Exception ex)
        {
            rstr_ParseResult = new string[] { "", ex.ToString(), "GetResponsesmartWebClientWoSWG" + "Level-1", "", "" };
            return rstr_ParseResult;
        }
    }

  
    #endregion

    #region Convertstream to byte
    public static byte[] ReadFully(Stream input)
    {
        byte[] buffer = new byte[16 * 1024];
        using (MemoryStream ms = new MemoryStream())
        {
            int read;
            while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                ms.Write(buffer, 0, read);
            }
            return ms.ToArray();
        }
    }
    public string UrlEncode(string strUrlValue)
    {
        strUrlValue = strUrlValue.Replace("&quot;", "\"");
        strUrlValue = strUrlValue.Replace("%", "%25");
        strUrlValue = strUrlValue.Replace("=", "%3D");
        strUrlValue = strUrlValue.Replace("+", "%2B");
        strUrlValue = strUrlValue.Replace(" ", "+");
        strUrlValue = strUrlValue.Replace("?", "%3F");
        strUrlValue = strUrlValue.Replace("/", "%2F");
        strUrlValue = strUrlValue.Replace("|", "%7C");
        strUrlValue = strUrlValue.Replace(";", "%3B");
        strUrlValue = strUrlValue.Replace("!", "%21");
        strUrlValue = strUrlValue.Replace("\"", "%22");
        strUrlValue = strUrlValue.Replace("#", "%23");
        strUrlValue = strUrlValue.Replace("$", "%24");
        strUrlValue = strUrlValue.Replace("&", "%26");
        strUrlValue = strUrlValue.Replace("'", "%27");
        strUrlValue = strUrlValue.Replace("(", "%28");
        strUrlValue = strUrlValue.Replace(")", "%29");
        strUrlValue = strUrlValue.Replace("*", "%2A");
        strUrlValue = strUrlValue.Replace(",", "%2C");
        //strUrlValue = strUrlValue.Replace("-", "%2D");
        strUrlValue = strUrlValue.Replace(":", "%3A");
        strUrlValue = strUrlValue.Replace("<", "%3C");
        strUrlValue = strUrlValue.Replace("=", "%3D");
        strUrlValue = strUrlValue.Replace(">", "%3E");
        strUrlValue = strUrlValue.Replace("@", "%40");
        strUrlValue = strUrlValue.Replace("[", "%5B");
        strUrlValue = strUrlValue.Replace("\\", "%5C");
        strUrlValue = strUrlValue.Replace("]", "%5D");
        strUrlValue = strUrlValue.Replace("^", "%5E");
        strUrlValue = strUrlValue.Replace("{", "%7B");
        strUrlValue = strUrlValue.Replace("}", "%7D");
        strUrlValue = strUrlValue.Replace("~", "%7E");
        return strUrlValue;
    }
    public string UrlDecode(string strUrlValue)
    {
        strUrlValue = strUrlValue.Replace("%25", "%");
        strUrlValue = strUrlValue.Replace("%2B", "+");
        strUrlValue = strUrlValue.Replace("+", " ");
        strUrlValue = strUrlValue.Replace("%3F", "?");
        strUrlValue = strUrlValue.Replace("%2F", "/");
        strUrlValue = strUrlValue.Replace("%7C", "|");
        strUrlValue = strUrlValue.Replace("%3B", ";");
        strUrlValue = strUrlValue.Replace("%21", "!");
        strUrlValue = strUrlValue.Replace("%22", "\"");
        strUrlValue = strUrlValue.Replace("%23", "#");
        strUrlValue = strUrlValue.Replace("%24", "$");
        strUrlValue = strUrlValue.Replace("%26", "&");
        strUrlValue = strUrlValue.Replace("%27", "'");
        strUrlValue = strUrlValue.Replace("%28", "(");
        strUrlValue = strUrlValue.Replace("%29", ")");
        strUrlValue = strUrlValue.Replace("%2A", "*");
        strUrlValue = strUrlValue.Replace("%2C", ",");
        strUrlValue = strUrlValue.Replace("%2D", "-");
        strUrlValue = strUrlValue.Replace("%3A", ":");
        strUrlValue = strUrlValue.Replace("%3C", "<");
        strUrlValue = strUrlValue.Replace("%3E", ">");
        strUrlValue = strUrlValue.Replace("%40", "@");
        strUrlValue = strUrlValue.Replace("%5B", "[");
        strUrlValue = strUrlValue.Replace("%5C", "\\");
        strUrlValue = strUrlValue.Replace("%5D", "]");
        strUrlValue = strUrlValue.Replace("%5E", "^");
        strUrlValue = strUrlValue.Replace("%7B", "{");
        strUrlValue = strUrlValue.Replace("%7D", "}");
        strUrlValue = strUrlValue.Replace("%7E", "~");
        return strUrlValue;
    }
    private static bool ValidateRemoteCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors policyErrors)
    {
        if (Convert.ToBoolean("true"))
        {
            return true;
        }
        else
        {
            return policyErrors == SslPolicyErrors.None;
        }
    }
    #endregion
  
}



