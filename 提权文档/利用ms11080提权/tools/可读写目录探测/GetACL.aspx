<%@ Page Language="C#" Debug="true" Trace="false" ValidateRequest="false" EnableViewStateMac="false" EnableViewState="true" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Security.AccessControl" %>
<%@ Import Namespace="System.Collections.Generic" %>
<%@ Import Namespace="System.Management" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Assembly Name="System.Management,Version=2.0.0.0,Culture=neutral,PublicKeyToken=B03F5F7F11D50A3A" %>
<html>
<head><title>.net ACL Searcher (Code By zcgonvh)</title></head>
<body>
<form runat="server" id="chkfrm">
<div style="text-align: center;">
    <h3><span style="color: red"></span></h3>
    <asp:textbox runat="server" id="iptPaths" height="99" columns="50" textmode="1"></asp:textbox><br />
    <asp:checkbox runat="server" id="is_Recusive" text="Recursive detection" checked="true"></asp:checkbox>
    <asp:checkbox runat="server" id="is_CheckFile" text="Check file" checked="false"></asp:checkbox>
    <asp:checkbox runat="server" id="is_ShowAllUserACL" text="Show all User's ACL" checked="false"></asp:checkbox><br />
    <asp:button runat="server" id="docheck" text="Check"></asp:button><br />
    <span>If you selected "Recursive detection" option , program will try enum all-SubDirectories in any directory , and get ACL to show.</span><br />
    <span>If you selected "Check file" option , program will try enum all-files in any directory , and get ACL to show (maybe slow).</span><br />
    <span>If you selected "Show all User ACL" option , program will show all ACL for any file or directory <br />(only show Allowed Execute file of current-user/users/everyone default).</span>
</div>
</form>
<div style="text-align: center;">
<form runat="server" id="retfrm" visible="false">
<asp:button runat="server" id="doret" text="Return"></asp:button>
</form>
</div>
</body>
</html>
<script runat="server">
    class ACL
    {
        private bool _is_ShowAllUserACL = false;
        private bool _is_CheckFile = false;
        private bool _is_Recusive = false;
        private string CurrentUser = "";
        public bool ShowAllUserACL { get { return _is_ShowAllUserACL; } set { _is_ShowAllUserACL = value; } }
        public bool CheckFile { get { return _is_CheckFile; } set { _is_CheckFile = value; } }
        public bool Recusive { get { return _is_Recusive; } set { _is_Recusive = value; } }
        public ACL(string[] Paths,bool is_ShowAllUserACL,bool is_CheckFile,bool is_Recusive)
        {
            CurrentUser = GetCurrentUserName();
            ShowAllUserACL = is_ShowAllUserACL;
            CheckFile = is_CheckFile;
            Recusive = is_Recusive;
            foreach (string path in Paths)
            {
                if (File.Exists(path))
                {
                    GetFileACL(new FileInfo(path));
                }
                else if (Directory.Exists(path))
                {
                    GetDirectoryACL(new DirectoryInfo(path));
                }
                else
                {
                    HttpContext.Current.Response.Write("<div style=\"color:red;text-align:center;\">" + path + "</div>File Not Found");
                }
            }
        }
        public void GetDirectoryACL(DirectoryInfo path)
        {
            bool is_write = false;
            try
            {
                DirectorySecurity sec = path.GetAccessControl(AccessControlSections.Access);
                foreach (FileSystemAccessRule rule in sec.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount)))
                {
                    if (!ShowAllUserACL && (rule.IdentityReference.Value == CurrentUser || rule.IdentityReference.Value == "Everyone" || rule.IdentityReference.Value == "BUILTIN\\Users") && (rule.AccessControlType == AccessControlType.Allow) && (rule.FileSystemRights.ToString() == "FullControl" || rule.FileSystemRights.ToString().ToLower().IndexOf("exec") != -1))
                    {
                        if (!is_write) { HttpContext.Current.Response.Write("<div style=\"color:red;text-align:center;\">" + path.FullName + "\\</div>"); is_write = true; }
                        HttpContext.Current.Response.Write("<span style=\"color:red\">" + rule.IdentityReference.Value + "</span>:<span style=\"color:green\">" + rule.AccessControlType + "</span>:" + rule.FileSystemRights.ToString()+"<br />");
                    }
                    else if (ShowAllUserACL)
                    {
                        if (!is_write) { HttpContext.Current.Response.Write("<div style=\"color:red;text-align:center;\">" + path.FullName + "</div>"); is_write = true; }
                        HttpContext.Current.Response.Write("<span style=\"color:red\">" + rule.IdentityReference.Value + "</span>:<span style=\"color:green\">" + rule.AccessControlType + "</span>:" + rule.FileSystemRights.ToString() + "<br />");
                    }
                }
            }
            catch (UnauthorizedAccessException) { if (ShowAllUserACL)HttpContext.Current.Response.Write("<div style=\"color:red;text-align:center;\">" + path.FullName + "\\</div>Access Denied<br />"); }
            catch (Exception) { if (ShowAllUserACL)HttpContext.Current.Response.Write("<div style=\"color:red;text-align:center;\">" + path.FullName + "\\</div>Unknown Error<br />"); }
            if (CheckFile)
            {
              try{
                  foreach (FileInfo fi in path.GetFiles()){GetFileACL(fi);}
                  }
              catch(Exception){}
            }
            if (Recusive)
            {
              try{
                  foreach (DirectoryInfo di in path.GetDirectories()){GetDirectoryACL(di);}
                  }
              catch(Exception){}
            }
        }
        public void GetFileACL(FileInfo path)
        {
            bool is_write = false;
            try
            {
                FileSecurity sec = path.GetAccessControl(AccessControlSections.Access);
                foreach (FileSystemAccessRule rule in sec.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount)))
                {
                    if (!ShowAllUserACL && (rule.IdentityReference.Value == CurrentUser || rule.IdentityReference.Value == "Everyone" || rule.IdentityReference.Value == "BUILTIN\\Users") && (rule.AccessControlType == AccessControlType.Allow) && (rule.FileSystemRights.ToString() == "FullControl" || rule.FileSystemRights.ToString().ToLower().IndexOf("exec")!=-1))
                    {
                        if (!is_write) { HttpContext.Current.Response.Write("<div style=\"color:red;text-align:center;\">" + path.FullName + "</div>"); is_write = true; }
                        HttpContext.Current.Response.Write("<span style=\"color:red\">" + rule.IdentityReference.Value + "</span>:<span style=\"color:green\">" + rule.AccessControlType + "</span>:" + rule.FileSystemRights.ToString() + "<br />");
                    }
                    else if (ShowAllUserACL)
                    {
                        if (!is_write) { HttpContext.Current.Response.Write("<div style=\"color:red;text-align:center;\">" + path.FullName + "</div>"); is_write = true; }
                        HttpContext.Current.Response.Write("<span style=\"color:red\">" + rule.IdentityReference.Value + "</span>:<span style=\"color:green\">" + rule.AccessControlType + "</span>:" + rule.FileSystemRights.ToString() + "<br />");
                    }
                }
            }
            catch (UnauthorizedAccessException) { if (ShowAllUserACL)HttpContext.Current.Response.Write("<div style=\"color:red;text-align:center;\">" + path.FullName + "\\</div>Access Denied<br />"); }
            catch (Exception) { if (ShowAllUserACL)HttpContext.Current.Response.Write("<div style=\"color:red;text-align:center;\">" + path.FullName + "\\</div>Unknown Error<br />"); }
        }
        public string GetCurrentUserName()
        {
            string UserName = "";
            try
            {
                ManagementObject MO_CurrentProcess =
                new ManagementObject("root\\CIMV2", "Win32_Process.Handle='" + Process.GetCurrentProcess().Id + "'", null);
                ManagementBaseObject UserInfo = MO_CurrentProcess.InvokeMethod("GetOwner", null, null);
                UserName = UserInfo["Domain"] + "\\" + UserInfo["User"];
            }
            catch (Exception)
            {
                UserName = "NT AUTHORITY\\NETWORK SERVICE";
            }
            return UserName;
        }
    }
    protected void Page_load(object sender, EventArgs e)
    {
        this.docheck.Click += new EventHandler(this.docheck_Click);
        this.doret.Click += new EventHandler(this.doret_Click);
        if(!IsPostBack){this.iptPaths.Text=Path.GetTempPath()+"\r\n"+Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)+"\\";}
    }
    private void docheck_Click(object sender, EventArgs e)
    {
        this.chkfrm.Visible = false;
        string[] Paths = iptPaths.Text.Split(new string[1] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
        new ACL(Paths,is_ShowAllUserACL.Checked,is_CheckFile.Checked,is_Recusive.Checked);
        this.retfrm.Visible = true;
    }
    private void doret_Click(object sender, EventArgs e)
    {
        Response.Redirect(Request.Url.AbsoluteUri);
    }
</script>

