import React, { useState } from "react";
import axios from "axios";
import jsPDF from "jspdf";

const API_BASE_URL = "http://127.0.0.1:5000"; // Update with Flask backend URL

const App = () => {
    const [url, setUrl] = useState("");
    const [scanData, setScanData] = useState(null);
    const [loading, setLoading] = useState(false);

    const handleScan = async () => {
        if (!url.trim()) {
            alert("❌ Please enter a valid URL");
            return;
        }

        setLoading(true);
        setScanData(null);

        try {
            const response = await axios.post(`${API_BASE_URL}/scan`, { url });
            setScanData(response.data);
        } catch (error) {
            console.error("API Error:", error);
            alert("Scan failed. Check Flask backend.");
        }

        setLoading(false);
    };

    const downloadReport = () => {
        const doc = new jsPDF();
        doc.text(`Security Report for ${url}`, 20, 20);
        doc.text(`Security Score: ${scanData.security_score}%`, 20, 40);

        let yPos = 60;
        Object.entries(scanData.threat_indicators).forEach(([category, data]) => {
            doc.text(`${category}: ${data.score} (${data.grade})`, 20, yPos);
            yPos += 10;
        });

        doc.text("Vulnerabilities:", 20, yPos + 10);
        scanData.vulnerabilities.forEach((vuln, i) => {
            doc.text(`${i + 1}. ${vuln}`, 20, yPos + 20 + i * 10);
        });

        doc.save("security-report.pdf");
    };

    return (
        <div style={{ maxWidth: "700px", margin: "40px auto", fontFamily: "Arial" }}>
            <h1>🔍 Web Vulnerability Scanner</h1>
            <input type="text" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="Enter URL" style={{ width: "80%", padding: "8px" }} />
            <button onClick={handleScan} disabled={loading} style={{ padding: "8px 15px", marginLeft: "10px" }}>
                {loading ? "Scanning..." : "Scan"}
            </button>

            {scanData && (
                <div style={{ marginTop: "20px", padding: "15px", border: "1px solid #ccc" }}>
                    <h2>🛡 Security Score: {scanData.security_score}%</h2>
                    <button onClick={downloadReport} style={{ marginTop: "10px", padding: "8px 15px" }}>📄 Download Report</button>
                </div>
            )}
        </div>
    );
};

export default App;
