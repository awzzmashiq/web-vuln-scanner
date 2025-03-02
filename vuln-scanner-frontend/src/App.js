import React, { useState } from "react";
import axios from "axios";

const App = () => {
    const [url, setUrl] = useState("");
    const [scans, setScans] = useState([]);
    const [loading, setLoading] = useState(false);

    const isValidURL = (input) => {
        const urlRegex = /^(https?:\/\/)([\da-z.-]+)\.([a-z.]{2,6})([\/\w .-]*)*\/?$/i;
        return urlRegex.test(input);
    };

    const handleScan = async () => {
        if (!url.trim() || !isValidURL(url.trim())) {
            alert("Please enter a valid URL starting with http:// or https://");
            return;
        }

        setScans([]); // Clear old results before new scan
        setLoading(true);

        try {
            const response = await axios.post("http://127.0.0.1:5000/scan",
                { url },
                { headers: { "Content-Type": "application/json" }, timeout: 60000 }
            );

            setScans([response.data]); // Store only the new scan result
        } catch (error) {
            console.error("API Error:", error);
            alert("Scan failed. Check Flask backend.");
        }

        setLoading(false);
    };

    return (
        <div style={{ maxWidth: "600px", margin: "40px auto", fontFamily: "Arial" }}>
            <h1>Web Vulnerability Scanner</h1>
            <div>
                <input
                    type="text"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder="Enter URL (e.g., http://example.com)"
                    style={{ width: "80%", padding: "8px", marginRight: "10px" }}
                />
                <button onClick={handleScan} disabled={loading} style={{ padding: "8px 15px" }}>
                    {loading ? "Scanning..." : "Scan"}
                </button>
            </div>

            <h2>Results:</h2>
            {scans.length > 0 ? (
                scans.map((scan, index) => (
                    <div key={index} style={{ padding: "10px", border: "1px solid #ccc", marginTop: "10px" }}>
                        <p><strong>Security Score:</strong> {scan.security_score}%</p>
                        <ul>
                            {scan.vulnerabilities.length > 0 ? (
                                scan.vulnerabilities.map((vuln, i) => <li key={i}>{vuln}</li>)
                            ) : (
                                <li>No vulnerabilities detected 🎉</li>
                            )}
                        </ul>
                    </div>
                ))
            ) : (
                <p>No scans yet.</p>
            )}
        </div>
    );
};

export default App;
