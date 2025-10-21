// UltimateAntiCheatAdvanced.cs
// Minimal comments; placeholders marked. Drop into Assets and attach/start at boot.

using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using UnityEngine;
using UnityEngine.Networking;

public class UltimateAntiCheatAdvanced : MonoBehaviour
{
    public string serverBaseUrl = "https://your.server.example"; // set to your server
    public string nonceEndpoint = "/nonce";
    public string attestEndpoint = "/attest";
    public string reportEndpoint = "/report";
    public string clientBuildId = "build-1";
    public bool enablePeriodicAttestation = true;
    public float attestationInterval = 60f;
    public bool logLocally = true;
    public bool sendToServer = true;
    public bool detectDebugger = true;
    public bool detectRootJailbreak = true;
    public bool detectKnownCheatApps = true;
    public bool detectFrida = true;
    public bool detectManagedTamper = true;
    public bool verifyCertificatePin = true;
    public string pinPubKeySha256 = ""; // PLACEHOLDER: set SHA256 of server public key (base64 or hex)
    private static UltimateAntiCheatAdvanced _instance;
    public static UltimateAntiCheatAdvanced Instance => _instance;
    private readonly object _lock = new object();
    private List<Finding> _findings = new List<Finding>();
    private Dictionary<string, string> expectedFileHashes = new Dictionary<string, string>()
    {
        // PLACEHOLDER: Insert expected file SHA256s keyed by absolute path or relative path used below.
        // Example: { "/path/to/Managed/Assembly-CSharp.dll", "ab12cd..." }
    };
    private string localStoreFile => Path.Combine(Application.persistentDataPath, "uac_local.bin");
    private byte[] localAesKey;
    private float _attestorTimer = 0f;
    private bool initialized = false;
    private void Awake()
    {
        if (_instance != null && _instance != this) { Destroy(gameObject); return; }
        _instance = this; DontDestroyOnLoad(gameObject); Initialize();
    }
    [Serializable]
    private class Finding { public string type; public string message; public double ts; public Dictionary<string,string> details; }
    private void Initialize()
    {
        if (initialized) return;
        initialized = true;
        localAesKey = GenerateAesKeyFromSeed(clientBuildId);
        LoadLocalState();
        StartCoroutine(StartupChecks());
        if (enablePeriodicAttestation) StartCoroutine(AttestationLoop());
    }
    private byte[] GenerateAesKeyFromSeed(string seed)
    {
        using (var sha = SHA256.Create()) return sha.ComputeHash(Encoding.UTF8.GetBytes(seed + Application.identifier));
    }
    private void LoadLocalState()
    {
        try
        {
            if (!File.Exists(localStoreFile)) return;
            var data = File.ReadAllBytes(localStoreFile);
            var plain = AesDecrypt(data, localAesKey);
            if (plain != null)
            {
                var s = Encoding.UTF8.GetString(plain);
                var obj = JsonUtility.FromJson<LocalStore>(s);
                if (obj != null && obj.findings != null) _findings = obj.findings.ToList();
            }
        }
        catch { }
    }
    private void SaveLocalState()
    {
        try
        {
            var obj = new LocalStore { findings = _findings.ToArray(), lastSaved = DateTime.UtcNow.ToString("o") };
            var s = JsonUtility.ToJson(obj);
            var enc = AesEncrypt(Encoding.UTF8.GetBytes(s), localAesKey);
            File.WriteAllBytes(localStoreFile, enc);
        }
        catch { }
    }
    [Serializable] private class LocalStore { public Finding[] findings; public string lastSaved; }
    private IEnumerator StartupChecks()
    {
        RunLightChecks();
        if (detectManagedTamper) yield return StartCoroutine(CheckManagedHashes());
    }
    private void RunLightChecks()
    {
        if (detectDebugger && IsDebuggerAttached()) Record("Debugger","Debugger attached",null);
        if (detectRootJailbreak) CheckRootJailbreak();
#if UNITY_ANDROID
        if (detectKnownCheatApps) DetectKnownCheatAppsAndroid();
        if (detectFrida) CheckFridaBinariesAndroid();
#endif
#if UNITY_IOS
        if (detectFrida) CheckFridaArtifactsIOS();
#endif
        CheckRuntimeInvariants();
    }
    private IEnumerator AttestationLoop()
    {
        while (true)
        {
            yield return new WaitForSeconds(attestationInterval);
            yield return StartCoroutine(PerformAttestation());
        }
    }
    private IEnumerator PerformAttestation()
    {
        string nonce = null;
        using (UnityWebRequest uw = UnityWebRequest.Get(serverBaseUrl + nonceEndpoint))
        {
            if (verifyCertificatePin) uw.certificateHandler = new PinningCertificateHandler(pinPubKeySha256);
            uw.timeout = 8;
            yield return uw.SendWebRequest();
            if (uw.result == UnityWebRequest.Result.Success) nonce = uw.downloadHandler.text.Trim();
            else { Record("AttestError","Nonce fetch failed", new Dictionary<string,string>{{"err",uw.error}}); yield break; }
        }
        var payload = CollectEvidence();
        var payloadJson = JsonUtility.ToJson(payload);
        var hmac = ComputeHmacBase64(nonce, payloadJson);
        var form = new WWWForm(); form.AddField("payload", payloadJson); form.AddField("hmac", hmac); form.AddField("build", clientBuildId);
        using (UnityWebRequest uw = UnityWebRequest.Post(serverBaseUrl + attestEndpoint, form))
        {
            if (verifyCertificatePin) uw.certificateHandler = new PinningCertificateHandler(pinPubKeySha256);
            uw.timeout = 10;
            yield return uw.SendWebRequest();
            if (uw.result == UnityWebRequest.Result.Success)
            {
                if (logLocally) Debug.Log("[UAC] Attestation OK");
                SaveLocalState();
            }
            else
            {
                Record("AttestFail","Attestation post failed", new Dictionary<string,string>{{"err",uw.error}});
            }
        }
    }
    private object CollectEvidence()
    {
        lock (_lock)
        {
            var ev = new Evidence
            {
                timestamp = DateTime.UtcNow.ToString("o"),
                build = clientBuildId,
                platform = Application.platform.ToString(),
                deviceModel = SystemInfo.deviceModel,
                deviceId = SystemInfo.deviceUniqueIdentifier,
                findings = _findings.TakeLast(10).ToArray()
            };
            return ev;
        }
    }
    [Serializable] private class Evidence { public string timestamp; public string build; public string platform; public string deviceModel; public string deviceId; public Finding[] findings; }
    private void Record(string type, string message, Dictionary<string,string> details)
    {
        lock (_lock)
        {
            var f = new Finding { type = type, message = message, ts = DateTime.UtcNow.Subtract(new DateTime(1970,1,1)).TotalSeconds, };
            f.details = details ?? new Dictionary<string,string>();
            _findings.Add(f);
            if (logLocally) Debug.LogWarning($"[UAC] {type}: {message}");
            if (sendToServer) StartCoroutine(SendReport(f));
        }
    }
    private IEnumerator SendReport(Finding f)
    {
        var json = JsonUtility.ToJson(new { build = clientBuildId, finding = f });
        string nonce = null;
        using (UnityWebRequest uw = UnityWebRequest.Get(serverBaseUrl + nonceEndpoint)) { if (verifyCertificatePin) uw.certificateHandler = new PinningCertificateHandler(pinPubKeySha256); uw.timeout = 6; yield return uw.SendWebRequest(); if (uw.result==UnityWebRequest.Result.Success) nonce=uw.downloadHandler.text.Trim(); else yield break; }
        var mac = ComputeHmacBase64(nonce, json);
        var form = new WWWForm(); form.AddField("report", json); form.AddField("hmac", mac); form.AddField("build", clientBuildId);
        using (UnityWebRequest uw = UnityWebRequest.Post(serverBaseUrl + reportEndpoint, form))
        {
            if (verifyCertificatePin) uw.certificateHandler = new PinningCertificateHandler(pinPubKeySha256);
            uw.timeout = 8; yield return uw.SendWebRequest();
            if (uw.result != UnityWebRequest.Result.Success) { if (logLocally) Debug.LogWarning("[UAC] Report failed: "+uw.error); }
        }
    }
    private static string ComputeHmacBase64(string key, string message)
    {
        try
        {
            var k = Encoding.UTF8.GetBytes(key);
            using (var h = new HMACSHA256(k)) return Convert.ToBase64String(h.ComputeHash(Encoding.UTF8.GetBytes(message)));
        }
        catch { return ""; }
    }
    private static byte[] AesEncrypt(byte[] data, byte[] key)
    {
        try
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key.Take(32).ToArray();
                aes.GenerateIV();
                using (var ms = new MemoryStream())
                {
                    ms.Write(aes.IV,0,aes.IV.Length);
                    using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write)) { cs.Write(data,0,data.Length); cs.FlushFinalBlock(); }
                    return ms.ToArray();
                }
            }
        }
        catch { return null; }
    }
    private static byte[] AesDecrypt(byte[] data, byte[] key)
    {
        try
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key.Take(32).ToArray();
                byte[] iv = new byte[16];
                Array.Copy(data, 0, iv, 0, 16);
                aes.IV = iv;
                using (var ms = new MemoryStream()) using (var cs = new CryptoStream(new MemoryStream(data,16,data.Length-16), aes.CreateDecryptor(), CryptoStreamMode.Read))
                { cs.CopyTo(ms); return ms.ToArray(); }
            }
        }
        catch { return null; }
    }

    private IEnumerator CheckManagedHashes()
    {
        try
        {
            var toCheck = new List<string>();
#if UNITY_EDITOR
            var managed = Path.Combine(Application.dataPath, "Managed");
            if (Directory.Exists(managed)) toCheck.AddRange(Directory.GetFiles(managed,"*.dll",SearchOption.TopDirectoryOnly));
#else
#if ENABLE_IL2CPP
            // PLACEHOLDER: add platform-specific binary paths to check
#else
            var folder = Path.Combine(Application.dataPath, "Managed");
            if (Directory.Exists(folder)) toCheck.AddRange(Directory.GetFiles(folder,"*.dll",SearchOption.TopDirectoryOnly));
#endif
#endif
            foreach (var f in toCheck)
            {
                var h = ComputeFileSHA256(f);
                string expected = null;
                expectedFileHashes.TryGetValue(f, out expected);
                if (!string.IsNullOrEmpty(expected) && !string.Equals(h, expected, StringComparison.OrdinalIgnoreCase))
                {
                    Record("ManagedTamper","Hash mismatch", new Dictionary<string,string>{{"file",f}});
                }
                yield return null;
            }
        }
        catch (Exception ex) { Record("HashCheckErr", ex.Message, null); }
    }

    private static string ComputeFileSHA256(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            using (var s = File.OpenRead(path)) using (var sha=SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(s)).Replace("-","").ToLowerInvariant();
        }
        catch { return null; }
    }

    private void CheckRuntimeInvariants()
    {
        try
        {
            float critical = GetCriticalInvariant();
            if (float.IsNaN(critical) || critical < -1e6f || critical > 1e6f) Record("InvariantFail","Critical invariant out of range", new Dictionary<string,string>{{"val",critical.ToString()}});
        }
        catch (Exception ex) { Record("InvariantErr", ex.Message, null); }
    }

    private float GetCriticalInvariant() { return 42f; } // PLACEHOLDER: return real critical game invariant

    private bool IsDebuggerAttached()
    {
        try { return System.Diagnostics.Debugger.IsAttached; } catch { return false; }
    }

    private void CheckRootJailbreak()
    {
#if UNITY_ANDROID
        try
        {
            string[] paths = { "/system/bin/su","/system/xbin/su","/sbin/su","/data/local/bin/su" };
            foreach (var p in paths) if (File.Exists(p)) { Record("Root","su found", new Dictionary<string,string>{{"path",p}}); return; }
            var tags = AndroidGetBuildTags();
            if (!string.IsNullOrEmpty(tags) && (tags.Contains("test-keys")||tags.Contains("dev-keys"))) Record("Root","build tags dev", new Dictionary<string,string>{{"tags",tags}});
        }
        catch { }
#endif
#if UNITY_IOS
        try
        {
            string[] jf = { "/Applications/Cydia.app","/private/var/lib/apt/" };
            foreach (var p in jf) if (File.Exists(p)) { Record("Jail","indicator", new Dictionary<string,string>{{"path",p}}); return; }
        }
        catch { }
#endif
    }

#if UNITY_ANDROID
    private void DetectKnownCheatAppsAndroid()
    {
        try
        {
            using (var jc = new AndroidJavaClass("com.unity3d.player.UnityPlayer"))
            {
                var ctx = jc.GetStatic<AndroidJavaObject>("currentActivity");
                var pm = ctx.Call<AndroidJavaObject>("getPackageManager");
                var apps = pm.Call<AndroidJavaObject>("getInstalledApplications", 0);
                int n = apps.Call<int>("size");
                var cheats = new string[] { "gameguardian","gameguardian.pro","org.sbtools.gamehack","igamegod","gbox","gameguardian" };
                for (int i=0;i<n;i++)
                {
                    var app = apps.Call<AndroidJavaObject>("get", i);
                    string pn = app.Get<string>("packageName");
                    foreach (var c in cheats) if (!string.IsNullOrEmpty(pn) && pn.ToLowerInvariant().Contains(c)) Record("KnownCheatApp","Detected installed package", new Dictionary<string,string>{{"package",pn}});
                }
            }
        } catch { }
    }

    private void CheckFridaBinariesAndroid()
    {
        try
        {
            var suspects = new [] { "/data/local/tmp/frida-server", "/data/local/frida-server" };
            foreach (var s in suspects) if (File.Exists(s)) Record("Frida","frida-server found", new Dictionary<string,string>{{"path",s}});
            var procDir = "/proc";
            if (Directory.Exists(procDir))
            {
                foreach (var d in Directory.GetDirectories(procDir))
                {
                    var cmdline = Path.Combine(d, "cmdline");
                    if (File.Exists(cmdline))
                    {
                        string txt = File.ReadAllText(cmdline);
                        if (txt.ToLowerInvariant().Contains("frida") || txt.ToLowerInvariant().Contains("gdbserver")) Record("SuspiciousProc","proc indicates hooking", new Dictionary<string,string>{{"proc",txt}});
                    }
                }
            }
        }
        catch { }
    }
#endif

#if UNITY_IOS
    private void CheckFridaArtifactsIOS()
    {
        try
        {
            var arr = new[] { "/usr/sbin/frida-server", "/Library/Frida" };
            foreach (var p in arr) if (File.Exists(p)) Record("FridaIOS","artifact found", new Dictionary<string,string>{{"path",p}});
        }
        catch { }
    }
#endif

    private IEnumerator SendToServerRaw(string path, byte[] body, string mime="application/json")
    {
        using (UnityWebRequest uw = new UnityWebRequest(path, "POST"))
        {
            uw.uploadHandler = new UploadHandlerRaw(body);
            uw.downloadHandler = new DownloadHandlerBuffer();
            uw.SetRequestHeader("Content-Type", mime);
            if (verifyCertificatePin) uw.certificateHandler = new PinningCertificateHandler(pinPubKeySha256);
            uw.timeout = 10;
            yield return uw.SendWebRequest();
        }
    }

    private static byte[] StringToBytes(string s) => Encoding.UTF8.GetBytes(s);

    private static byte[] HexToBytes(string hex)
    {
        if (string.IsNullOrEmpty(hex)) return null;
        hex = hex.Replace(" ","").Replace("-","");
        var len = hex.Length/2; var res = new byte[len];
        for (int i=0;i<len;i++) res[i]=Convert.ToByte(hex.Substring(i*2,2),16);
        return res;
    }

    private static string BytesToHex(byte[] b) { var sb=new StringBuilder(b.Length*2); foreach(var x in b) sb.AppendFormat("{0:x2}",x); return sb.ToString(); }

    private static string ComputeFileShaHex(string path)
    {
        try { using(var s=File.OpenRead(path)) using(var sha=SHA256.Create()){return BitConverter.ToString(sha.ComputeHash(s)).Replace("-","").ToLowerInvariant();} }
        catch { return null; }
    }

    private IEnumerator PeriodicIntegrityCheck()
    {
        while (true)
        {
            yield return new WaitForSeconds(Mathf.Max(10f, attestationInterval/2f));
            if (detectManagedTamper) yield return StartCoroutine(CheckManagedHashes());
        }
    }

    private IEnumerator SendToServerWithPin(string url, WWWForm form)
    {
        using (UnityWebRequest uw = UnityWebRequest.Post(url, form))
        {
            if (verifyCertificatePin) uw.certificateHandler = new PinningCertificateHandler(pinPubKeySha256);
            uw.timeout = 8; yield return uw.SendWebRequest();
            if (uw.result != UnityWebRequest.Result.Success) Record("NetErr","send failed", new Dictionary<string,string>{{"err",uw.error}});
        }
    }

    private static string ComputeHmacHexBytes(string key, string msg)
    {
        try { var k=Encoding.UTF8.GetBytes(key); using(var h=new HMACSHA256(k)){return BytesToHex(h.ComputeHash(Encoding.UTF8.GetBytes(msg)));} }
        catch { return ""; }
    }

    // Certificate pinning handler
    private class PinningCertificateHandler : CertificateHandler
    {
        private readonly string pinnedHash; // hex or base64
        public PinningCertificateHandler(string pin) { pinnedHash = pin ?? ""; }
        protected override bool ValidateCertificate(byte[] certData)
        {
            try
            {
                using (var sha = SHA256.Create())
                {
                    var pub = sha.ComputeHash(certData);
                    var hex = BytesToHex(pub);
                    if (string.IsNullOrEmpty(pinnedHash)) return true;
                    var clean = pinnedHash.Replace(" ", "").Replace("-", "").ToLowerInvariant();
                    if (clean.Length==hex.Length)
                    {
                        if (hex.Equals(clean, StringComparison.OrdinalIgnoreCase)) return true;
                    }
                    else
                    {
                        var b64 = Convert.ToBase64String(pub);
                        if (pinnedHash.Equals(b64)) return true;
                    }
                }
            }
            catch { }
            return false;
        }
    }

    private static string BytesToBase64(byte[] b) => Convert.ToBase64String(b);

    private IEnumerator SendToServerCoroutine(string endpoint, byte[] body)
    {
        var url = serverBaseUrl + endpoint;
        using (UnityWebRequest uw = new UnityWebRequest(url, "POST"))
        {
            uw.uploadHandler = new UploadHandlerRaw(body);
            uw.downloadHandler = new DownloadHandlerBuffer();
            uw.SetRequestHeader("Content-Type","application/octet-stream");
            uw.timeout = 10;
            yield return uw.SendWebRequest();
            if (uw.result != UnityWebRequest.Result.Success) Record("NetErr","post failed", new Dictionary<string,string>{{"err",uw.error}});
        }
    }

    private IEnumerator SendReportManual(Finding f)
    {
        var json = JsonUtility.ToJson(f);
        yield return StartCoroutine(SendToServerWithPin(serverBaseUrl + reportEndpoint, new WWWForm() { } )); // placeholder
    }

#if UNITY_ANDROID
    private string AndroidGetBuildTags()
    {
        try { using (var jc = new AndroidJavaClass("android.os.Build")) return jc.GetStatic<string>("TAGS"); } catch { return null; }
    }
#endif

    private static byte[] ToBytes(string s) => Encoding.UTF8.GetBytes(s);

    private static string AesKeyHex(byte[] k) => BytesToHex(k);

    // minimal GUI to trigger checks (Editor only)
#if UNITY_EDITOR
    private void OnGUI()
    {
        GUILayout.BeginVertical("box");
        GUILayout.Label("UltimateAntiCheatAdvanced");
        if (GUILayout.Button("Run Quick")) RunLightChecks();
        if (GUILayout.Button("Force Attest Now")) StartCoroutine(PerformAttestation());
        GUILayout.Label("Findings: "+_findings.Count);
        foreach (var f in _findings.TakeLast(10)) GUILayout.Label($"[{f.type}] {f.message}");
        GUILayout.EndVertical();
    }
#endif
}
