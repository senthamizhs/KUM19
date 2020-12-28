﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

// 
// This source code was auto-generated by Microsoft.VSDesigner, Version 4.0.30319.42000.
// 
#pragma warning disable 1591

namespace IPHelp.Route_Ip {
    using System;
    using System.Web.Services;
    using System.Diagnostics;
    using System.Web.Services.Protocols;
    using System.Xml.Serialization;
    using System.ComponentModel;
    
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Web.Services", "4.6.1038.0")]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Web.Services.WebServiceBindingAttribute(Name="Service1Soap", Namespace="http://tempuri.org/")]
    public partial class Service1 : System.Web.Services.Protocols.SoapHttpClientProtocol {
        
        private System.Threading.SendOrPostCallback SendRequestOperationCompleted;
        
        private System.Threading.SendOrPostCallback SendRequestWithHttpOperationCompleted;
        
        private bool useDefaultCredentialsSetExplicitly;
        
        /// <remarks/>
        public Service1() {
            this.Url = global::IPHelp.Properties.Settings.Default.IPHelp_Route_Ip_Service1;
            if ((this.IsLocalFileSystemWebService(this.Url) == true)) {
                this.UseDefaultCredentials = true;
                this.useDefaultCredentialsSetExplicitly = false;
            }
            else {
                this.useDefaultCredentialsSetExplicitly = true;
            }
        }
        
        public new string Url {
            get {
                return base.Url;
            }
            set {
                if ((((this.IsLocalFileSystemWebService(base.Url) == true) 
                            && (this.useDefaultCredentialsSetExplicitly == false)) 
                            && (this.IsLocalFileSystemWebService(value) == false))) {
                    base.UseDefaultCredentials = false;
                }
                base.Url = value;
            }
        }
        
        public new bool UseDefaultCredentials {
            get {
                return base.UseDefaultCredentials;
            }
            set {
                base.UseDefaultCredentials = value;
                this.useDefaultCredentialsSetExplicitly = true;
            }
        }
        
        /// <remarks/>
        public event SendRequestCompletedEventHandler SendRequestCompleted;
        
        /// <remarks/>
        public event SendRequestWithHttpCompletedEventHandler SendRequestWithHttpCompleted;
        
        /// <remarks/>
        [System.Web.Services.Protocols.SoapDocumentMethodAttribute("http://tempuri.org/SendRequest", RequestNamespace="http://tempuri.org/", ResponseNamespace="http://tempuri.org/", Use=System.Web.Services.Description.SoapBindingUse.Literal, ParameterStyle=System.Web.Services.Protocols.SoapParameterStyle.Wrapped)]
        public string SendRequest(string strUrl, string strMethod, string strSoapAction, string strRequestData) {
            object[] results = this.Invoke("SendRequest", new object[] {
                        strUrl,
                        strMethod,
                        strSoapAction,
                        strRequestData});
            return ((string)(results[0]));
        }
        
        /// <remarks/>
        public void SendRequestAsync(string strUrl, string strMethod, string strSoapAction, string strRequestData) {
            this.SendRequestAsync(strUrl, strMethod, strSoapAction, strRequestData, null);
        }
        
        /// <remarks/>
        public void SendRequestAsync(string strUrl, string strMethod, string strSoapAction, string strRequestData, object userState) {
            if ((this.SendRequestOperationCompleted == null)) {
                this.SendRequestOperationCompleted = new System.Threading.SendOrPostCallback(this.OnSendRequestOperationCompleted);
            }
            this.InvokeAsync("SendRequest", new object[] {
                        strUrl,
                        strMethod,
                        strSoapAction,
                        strRequestData}, this.SendRequestOperationCompleted, userState);
        }
        
        private void OnSendRequestOperationCompleted(object arg) {
            if ((this.SendRequestCompleted != null)) {
                System.Web.Services.Protocols.InvokeCompletedEventArgs invokeArgs = ((System.Web.Services.Protocols.InvokeCompletedEventArgs)(arg));
                this.SendRequestCompleted(this, new SendRequestCompletedEventArgs(invokeArgs.Results, invokeArgs.Error, invokeArgs.Cancelled, invokeArgs.UserState));
            }
        }
        
        /// <remarks/>
        [System.Web.Services.Protocols.SoapDocumentMethodAttribute("http://tempuri.org/SendRequestWithHttp", RequestNamespace="http://tempuri.org/", ResponseNamespace="http://tempuri.org/", Use=System.Web.Services.Description.SoapBindingUse.Literal, ParameterStyle=System.Web.Services.Protocols.SoapParameterStyle.Wrapped)]
        public string[] SendRequestWithHttp(string URL, string sessionid, string method, string parameter) {
            object[] results = this.Invoke("SendRequestWithHttp", new object[] {
                        URL,
                        sessionid,
                        method,
                        parameter});
            return ((string[])(results[0]));
        }
        
        /// <remarks/>
        public void SendRequestWithHttpAsync(string URL, string sessionid, string method, string parameter) {
            this.SendRequestWithHttpAsync(URL, sessionid, method, parameter, null);
        }
        
        /// <remarks/>
        public void SendRequestWithHttpAsync(string URL, string sessionid, string method, string parameter, object userState) {
            if ((this.SendRequestWithHttpOperationCompleted == null)) {
                this.SendRequestWithHttpOperationCompleted = new System.Threading.SendOrPostCallback(this.OnSendRequestWithHttpOperationCompleted);
            }
            this.InvokeAsync("SendRequestWithHttp", new object[] {
                        URL,
                        sessionid,
                        method,
                        parameter}, this.SendRequestWithHttpOperationCompleted, userState);
        }
        
        private void OnSendRequestWithHttpOperationCompleted(object arg) {
            if ((this.SendRequestWithHttpCompleted != null)) {
                System.Web.Services.Protocols.InvokeCompletedEventArgs invokeArgs = ((System.Web.Services.Protocols.InvokeCompletedEventArgs)(arg));
                this.SendRequestWithHttpCompleted(this, new SendRequestWithHttpCompletedEventArgs(invokeArgs.Results, invokeArgs.Error, invokeArgs.Cancelled, invokeArgs.UserState));
            }
        }
        
        /// <remarks/>
        public new void CancelAsync(object userState) {
            base.CancelAsync(userState);
        }
        
        private bool IsLocalFileSystemWebService(string url) {
            if (((url == null) 
                        || (url == string.Empty))) {
                return false;
            }
            System.Uri wsUri = new System.Uri(url);
            if (((wsUri.Port >= 1024) 
                        && (string.Compare(wsUri.Host, "localHost", System.StringComparison.OrdinalIgnoreCase) == 0))) {
                return true;
            }
            return false;
        }
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Web.Services", "4.6.1038.0")]
    public delegate void SendRequestCompletedEventHandler(object sender, SendRequestCompletedEventArgs e);
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Web.Services", "4.6.1038.0")]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    public partial class SendRequestCompletedEventArgs : System.ComponentModel.AsyncCompletedEventArgs {
        
        private object[] results;
        
        internal SendRequestCompletedEventArgs(object[] results, System.Exception exception, bool cancelled, object userState) : 
                base(exception, cancelled, userState) {
            this.results = results;
        }
        
        /// <remarks/>
        public string Result {
            get {
                this.RaiseExceptionIfNecessary();
                return ((string)(this.results[0]));
            }
        }
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Web.Services", "4.6.1038.0")]
    public delegate void SendRequestWithHttpCompletedEventHandler(object sender, SendRequestWithHttpCompletedEventArgs e);
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Web.Services", "4.6.1038.0")]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    public partial class SendRequestWithHttpCompletedEventArgs : System.ComponentModel.AsyncCompletedEventArgs {
        
        private object[] results;
        
        internal SendRequestWithHttpCompletedEventArgs(object[] results, System.Exception exception, bool cancelled, object userState) : 
                base(exception, cancelled, userState) {
            this.results = results;
        }
        
        /// <remarks/>
        public string[] Result {
            get {
                this.RaiseExceptionIfNecessary();
                return ((string[])(this.results[0]));
            }
        }
    }
}

#pragma warning restore 1591